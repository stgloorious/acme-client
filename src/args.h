/** 
 * @file args.h
 *
 * This program is free software: you can redistribute it and/or modify it 
 * under the terms of the GNU General Public License as published by 
 * the Free Software Foundation, either version 3 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, 
 * but WITHOUT ANY WARRANTY; without even the implied warranty 
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program. If not, see <https://www.gnu.org/licenses/>. 
 *
 * Copyright 2022 Stefan Gloor
 *
 */

const char* argp_program_version = "acme-client v0.1\n"
                        "Copyright (C) 2022 Stefan Gloor\n"
                        "License GPLv3: GNU GPL version 3 <https://gnu.org/licenses/gpl.html>.\n"
                        "This is free software: you are free to change and redistribute it.\n"
                        "There is NO WARRANTY, to the extent permitted by law.";
const char* argp_program_bug_address = "<code@stefan-gloor.ch>";

static char doc[] = "Simple ACME client written in C";
static char args_doc[] = "CHALLENGE TYPE {dns01 | http01}";


static struct argp_option options[] = {
        {"dir",      'u', "DIR_URL",      0,
                "Directory URL of the ACME server that should be used.", 0},
        {"record",   'r', "IPv4_ADDRESS", 0,
                "IPv4 the HTTP server should bind to", 0},
        {"port", 'p', "PORT", 0, "Port number the HTTP server should bind to", 0},
        {"domain",   'd', "DOMAIN",       0,
                "Domain for which to request the certificate. Can be used "
                        "multiple times.", 0},
        {"cert", 'c', "CERTFILE", 0,
                "CA certificate file used by the ACME server", 0},
        {"agree-tos", 'y', 0, OPTION_ARG_OPTIONAL, 
                "Always agree to the terms of service", 0},
        {"verbose",  'v', 0,         0, "Produce verbose output", 0},
        { 0 }
};

struct arguments {
        char* challenge_type;
        char* dir_url;
        char* record;
        char* port;
        char* server_cert;
        struct string_node* domain_list;
        int ndomain;
        int tos_agree;
        int verbose;
};

static error_t 
parse_opt (int key, char* arg, struct argp_state *state)
{
        struct arguments *arguments = state->input;
        switch (key){
                case 'u':
                        arguments->dir_url = arg;
                        break;
                case 'r':
                        arguments->record = arg;
                        break;
                case 'd':
                        arguments->domain_list = 
                                string_list_append(arguments->domain_list, arg);
                        assert(arguments->domain_list);
                        arguments->ndomain++;
                        break;
                case 'v':
                        arguments->verbose = 1;
                        break;
                case 'y':
                        arguments->tos_agree = 1;
                        break;
                case 'p':
                        arguments->port = arg;
                        break;
                case 'c':
                        arguments->server_cert = arg;
                        break;
                case ARGP_KEY_NO_ARGS:
                        argp_usage(state);
                        break;
                case ARGP_KEY_ARG:
                        if (*arguments->dir_url == '\0') {
                                argp_error(state, "--dir DIR_URL is required!");
                                return ARGP_ERR_UNKNOWN;
                        }
                        if (arguments->ndomain == 0) {
                                argp_error(state, "--domain DOMAIN is "
                                                "required!");
                                return ARGP_ERR_UNKNOWN;
                        }
                        
                        arguments->challenge_type = arg;
                        state->next = state->argc;
                        
                        if (strcmp(arguments->challenge_type, "http01") &&
                                strcmp(arguments->challenge_type, "dns01")){
                                argp_error(state, "CHALLENGE_TYPE must be " 
                                                "either 'http01' or 'dns01'");
                                return ARGP_ERR_UNKNOWN;
                        }

                        break;
                default:
                        return ARGP_ERR_UNKNOWN;
        }
        return 0;
};

static struct argp argp = {options, parse_opt, args_doc, doc, NULL, NULL, NULL};
