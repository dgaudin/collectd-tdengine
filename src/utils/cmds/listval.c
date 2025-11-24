/**
 * collectd - src/utils_cmd_listval.c
 * Copyright (C) 2008       Florian octo Forster
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Authors:
 *   Florian octo Forster <octo at collectd.org>
 **/

#include "collectd.h"

#include "plugin.h"
#include "utils/common/common.h"

#include "utils/cmds/listval.h"
#include "utils/cmds/getval.h"
#include "utils/cmds/parse_option.h"
#include "utils_cache.h"

cmd_status_t cmd_handle_getval2(FILE *, char *);

cmd_status_t cmd_parse_listval(size_t argc, char **argv,
                               const cmd_options_t *opts
                               __attribute__((unused)),
                               cmd_error_handler_t *err) {
  if (argc != 0) {
    cmd_error(CMD_PARSE_ERROR, err, "Garbage after end of command: `%s'.",
              argv[0]);
    return CMD_PARSE_ERROR;
  }

  return CMD_OK;
} /* cmd_status_t cmd_parse_listval */

#define free_everything_and_return(status)                                     \
  do {                                                                         \
    for (size_t j = 0; j < number; j++) {                                      \
      sfree(names[j]);                                                         \
      names[j] = NULL;                                                         \
    }                                                                          \
    sfree(names);                                                              \
    sfree(times);                                                              \
    return status;                                                             \
  } while (0)

#define print_to_socket(fh, ...)                                               \
  do {                                                                         \
    if (fprintf(fh, __VA_ARGS__) < 0) {                                        \
      WARNING("handle_listval: failed to write to socket #%i: %s", fileno(fh), \
              STRERRNO);                                                       \
      free_everything_and_return(CMD_ERROR);                                   \
    }                                                                          \
    fflush(fh);                                                                \
  } while (0)

cmd_status_t cmd_handle_listval(FILE *fh, char *buffer) {
  cmd_error_handler_t err = {cmd_error_fh, fh};
  cmd_status_t status;
  cmd_t cmd;

  char **names = NULL;
  cdtime_t *times = NULL;
  size_t number = 0;

  DEBUG("utils_cmd_listval: handle_listval (fh = %p, buffer = %s);", (void *)fh,
        buffer);

  if ((status = cmd_parse(buffer, &cmd, NULL, &err)) != CMD_OK)
    return status;
  if (cmd.type != CMD_LISTVAL) {
    cmd_error(CMD_UNKNOWN_COMMAND, &err, "Unexpected command: `%s'.",
              CMD_TO_STRING(cmd.type));
    free_everything_and_return(CMD_UNKNOWN_COMMAND);
  }

  status = uc_get_names(&names, &times, &number);
  if (status != 0) {
    DEBUG("command listval: uc_get_names failed with status %i", status);
    cmd_error(CMD_ERROR, &err, "uc_get_names failed.");
    free_everything_and_return(CMD_ERROR);
  }

  print_to_socket(fh, "%i Value%s found\n", (int)number,
                  (number == 1) ? "" : "s");
  for (size_t i = 0; i < number; i++)
    print_to_socket(fh, "%.3f %s\n", CDTIME_T_TO_DOUBLE(times[i]), names[i]);

  free_everything_and_return(CMD_OK);
} /* cmd_status_t cmd_handle_listval */



cmd_status_t cmd_handle_getallval(FILE *fh, char *buffer) {
  char **names = NULL;
  cdtime_t *times = NULL;
  size_t number = 0;
  cmd_status_t final_status = CMD_OK;

  /* No need to parse the command buffer, GETALLVAL takes no arguments */
  (void)buffer; /* Suppress unused parameter warning */

  if (uc_get_names(&names, &times, &number) != 0) {
    if (fprintf(fh, "Error: Failed to get value names from cache.\n") < 0) {
      WARNING("handle_getallval: failed to write error message to socket #%i: %s",
              fileno(fh), STRERRNO);
    }
    fflush(fh);
    return CMD_ERROR;
  }

  for (size_t i = 0; i < number; i++) {
    gauge_t *rates = NULL;
    size_t rates_num = 0;
    const data_set_t *ds;
    value_list_t vl = {0};

    /* Get rates for this metric - rates remains NULL on failure */
    if (uc_get_rate_by_name(names[i], &rates, &rates_num) != 0) {
      continue; /* Value may have expired, just skip it. */
    }

    /* Parse identifier string: "host/plugin-instance/type-instance" */
    if (parse_identifier_vl(names[i], &vl) != 0) {
      sfree(rates);
      continue; /* Should not happen if name from uc_get_names is valid. */
    }

    ds = plugin_get_ds(vl.type);
    if (ds == NULL || ds->ds_num != rates_num) {
      sfree(rates);
      continue; /* Unknown type or data mismatch. */
    }

    /* Print identifier, e.g., "myhost/cpu-0/cpu-idle" */
    if (fprintf(fh, "%s ", names[i]) < 0) {
      WARNING("handle_getallval: failed to write identifier to socket #%i: %s",
              fileno(fh), STRERRNO);
      final_status = CMD_ERROR;
      sfree(rates);
      break; /* Abort on socket write error */
    }

    /* Print each data source and its value, e.g., "value=1.234" */
    for (size_t j = 0; j < rates_num; j++) {
      char value_str[32];
      if (isnan(rates[j])) {
        sstrncpy(value_str, "U", sizeof(value_str));
      } else {
        ssnprintf(value_str, sizeof(value_str), "%.15g", rates[j]);
      }

      if (fprintf(fh, "%s=%s%s", ds->ds[j].name, value_str,
                  (j < rates_num - 1) ? " " : "") < 0) {
        WARNING("handle_getallval: failed to write value to socket #%i: %s",
                fileno(fh), STRERRNO);
        final_status = CMD_ERROR;
        break;
      }
    }

    /* If fprintf failed in the inner loop, stop trying to write */
    if (final_status != CMD_OK) {
      sfree(rates);
      break;
    }

    if (fprintf(fh, "\n") < 0) {
      WARNING("handle_getallval: failed to write newline to socket #%i: %s",
              fileno(fh), STRERRNO);
      final_status = CMD_ERROR;
      sfree(rates);
      break;
    }

    sfree(rates);
  }

  fflush(fh);

  /* Free memory allocated by uc_get_names */
  for (size_t i = 0; i < number; i++) {
    sfree(names[i]);
  }
  sfree(names);
  sfree(times);

  return final_status;
}


/*
cmd_status_t cmd_handle_getval_data(FILE *fh, char *buffer) {
	cmd_error_handler_t err = {cmd_error_fh, fh};
	cmd_status_t status;
	cmd_t cmd;

	gauge_t *values;
	size_t values_num;
	const data_set_t *ds;




	if ((fh == NULL) || (buffer == NULL))
		return -1;


	DEBUG("utils_cmd_getval: cmd_handle_getval (fh = %p, buffer = %s);",
			(void *)fh, buffer);

	if ((status = cmd_parse(buffer, &cmd, NULL, &err)) != CMD_OK)
		return status;
	if (cmd.type != CMD_GETVAL) {
		cmd_error(CMD_UNKNOWN_COMMAND, &err, "Unexpected command: `%s'.",
				CMD_TO_STRING(cmd.type));
		cmd_destroy(&cmd);
		return CMD_UNKNOWN_COMMAND;
	}

	ds = plugin_get_ds(cmd.cmd.getval.identifier.type);
	if (ds == NULL) {
		DEBUG("cmd_handle_getval: plugin_get_ds (%s) == NULL;",
				cmd.cmd.getval.identifier.type);
		cmd_error(CMD_ERROR, &err, "Type `%s' is unknown.\n",
				cmd.cmd.getval.identifier.type);
		cmd_destroy(&cmd);
		return -1;
	}

	values = NULL;
	values_num = 0;
	status =
		uc_get_rate_by_name(cmd.cmd.getval.raw_identifier, &values, &values_num);
	if (status != 0) {
		cmd_error(CMD_ERROR, &err, "No such value.");
		cmd_destroy(&cmd);
		return CMD_ERROR;
	}

	if (ds->ds_num != values_num) {
		ERROR("ds[%s]->ds_num = %" PRIsz ", "
				"but uc_get_rate_by_name returned %" PRIsz " values.",
				ds->type, ds->ds_num, values_num);
		cmd_error(CMD_ERROR, &err, "Error reading value from cache.");
		sfree(values);
		cmd_destroy(&cmd);
		return CMD_ERROR;
	}
	for (size_t i = 0; i < values_num; i++) {
		print_to_socket(fh, "%s=", ds->ds[i].name);
		if (isnan(values[i])) {
			print_to_socket(fh, "NaN\n");
		} else {
			print_to_socket(fh, "%12e\n", values[i]);
		}
	}

	sfree(values);
	cmd_destroy(&cmd);

	return CMD_OK;
}*/ /* cmd_status_t cmd_handle_getval */
