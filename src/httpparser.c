#include "httpparser.h"
#include <pcre2.h>
#include <stdio.h>

#ifndef HTTP_PATTERNS
#define HTTP_PATTERNS
//RFC 5234
#define ALPHA "A-Za-z"
#define DIGIT "0-9"
#define HEXDIG DIGIT "A-F"
#define VCHAR "\\x21-\\x7e"
#define CRLF "\\r\\n"

//RFC 3986
#define scheme "(?'scheme'(?>[" ALPHA "][" ALPHA DIGIT "+\\-.]*+))"

#define port "(?'port'(?>[" DIGIT "]*+))"

#define dec_octet "(?:[" DIGIT "]|[1-9][" DIGIT "]|1[" DIGIT "]{2}|2[0-4]" DIGIT "|25[0-5])"
#define IPv4address "(?>" dec_octet" \\." dec_octet "\\." dec_octet "\\." dec_octet ")"

#define h16 "[" HEXDIG "]{1,4}"
#define ls32 "(?:" h16 ":" h16 "|" IPv4address ")"


#define IPv6address "(?'IPv6address'" \
    "(?:(?:" h16 ":){6}" ls32 ")|" \
    "(?:::(?:" h16 ":){5}" ls32 ")|" \
    "(?:(?:"h16")?::(?:"h16":){4}"ls32")|" \
    "(?:(?:(?:" h16 ":){0,1}" h16 ")?::(?:" h16 ":){3}" ls32 ")|" \
    "(?:(?:(?:" h16 ":){0,2}" h16 ")?::(?:" h16 ":){2}" ls32 ")|" \
    "(?:(?:(?:" h16 ":){0,3}" h16 ")?::" h16 ":" ls32 ")|" \
    "(?:(?:(?:" h16 ":){0,4}" h16 ")?::" ls32 ")|" \
    "(?:(?:(?:" h16 ":){0,5}" h16 ")?::" h16 ")|" \
    "(?:(?:(?:" h16 ":){0,6}" h16 ")?::))"

#define unreserved ALPHA DIGIT "\\-._~"
#define sub_delims "!$&'()*+,;="

#define IPvFuture "(?'IPvFuture'v[" HEXDIG "]++\\.[" unreserved sub_delims ":]++)"
#define IP_literal "(?'IP_literal'\\[(?>" IPv6address "|" IPvFuture ")\\])"

#define pct_encoded "%[" HEXDIG "]{2}"
#define reg_name "(?'reg_name'(?>(?:[" unreserved sub_delims "]++|" pct_encoded ")*))"

#define uri_rule_host "(?'host'" IP_literal "|(?'IPv4address'" IPv4address ")|" reg_name ")"
#define userInfo "(?'userinfo'(?>(?:[" unreserved sub_delims ":]++|" pct_encoded ")*))"
#define authority "(?'authority'(?:" userInfo "@)?" uri_rule_host "(?::" port ")?)"

#define pchar "[" unreserved sub_delims ":@]++|" pct_encoded
#define segment "(?>(?:" pchar ")*)"
#define segment_nz "(?>(?:" pchar ")+)"

#define path_abempty "(?'path_abempty'(?:\\/" segment ")*)"
#define path_absolute "(?'path_absolute'\\/(?:" segment_nz "(?:\\/" segment ")*)?)"
#define path_rootless "(?'path_rootless'" segment_nz "(?:\\/" segment ")*)"
#define path_empty "(?'path_empty')"

#define query "(?'query'(?>(?:" pchar "|[\\/?])*))"
#define fragment "(?'fragment'(?>(?:" pchar "|[\\/?])*))"

#define hier_part "(?'hier_part'\\/\\/" authority path_abempty "|" path_absolute "|" path_rootless "|" path_empty ")"
#define absolute_URI "(?'absolute_URI'" scheme ":" hier_part "(?:\\?" query ")?(?:\\#" fragment ")?)"

//RFC 9112
#define OWS "(?:[ \\t]*+)"
#define tchar DIGIT ALPHA "!#$%&'*+-.^_`|~"
#define obs_text "\\x80-\\xFF"
#define absolute_path "(?'absolute_path'(?:\\/" segment ")++)"
#define token "(?:[" tchar "]++)"
#define field_name "(?'field_name'" token ")"

#define field_vchar VCHAR obs_text
#define field_content "(?:[" field_vchar "](?:[ \\t" field_vchar "]+[" field_vchar "])?)"
#define field_value "(?'field_value'" field_content "*)"

//RFC 9110

#define HTTP_version "(?'http_version'HTTP\\/(?'http_version_major'[" DIGIT "])\\.(?'http_version_minor'[" DIGIT "]))"
#define status_code "(?'status_code'[" DIGIT "]{3})"
#define reason_phrase "(?'reason_phrase'(?:\t| |[" VCHAR "]|[" obs_text "])++)"
#define status_line "(?'status_line'" HTTP_version " " status_code " " reason_phrase "?)"

#define http_rule_method "(?'method'" token ")"

#define origin_form "(?'origin_form'" absolute_path "(?:[?]" query")?)"
#define absolute_form "(?'absolute_form'" absolute_URI ")"

#define authority_form "(?'authority_form'" uri_rule_host ":" port ")"
#define asterix_form "(?'asterix_form'[*])"

#define request_target "(?'request_target'" origin_form "|" absolute_form "|" authority_form "|" asterix_form ")"

#define request_line "(?'request_line'" http_rule_method " " request_target " " HTTP_version ")"

#define start_line "(?'start_line'" request_line "|" status_line ")"

#define field_line "(?:" field_name ":" OWS field_value OWS ")"

#define http_message "(?:" start_line CRLF "(?:" field_line CRLF ")*" CRLF "(?'message_body'.*)?)"
#define header_pattern "(?:" field_line CRLF ")"

#define debug_message "(?:" start_line CRLF ")"
#endif

PCRE2_SPTR http_message_pattern = (PCRE2_SPTR) http_message;
PCRE2_SPTR http_header_pattern = (PCRE2_SPTR) header_pattern;

pcre2_code* http_message_code = NULL;
pcre2_code* http_header_code = NULL;

uint32_t http_message_name_count;
uint32_t http_header_name_count;

void write_to_file_pattern(){
    FILE* f = fopen("pattern.txt", "w");
    fprintf(f, "%s", header_pattern);
    fclose(f);
}

void print_substring(pcre2_match_data* match_data, PCRE2_SPTR name)
{
    PCRE2_SIZE buflen;
    PCRE2_UCHAR* buffer;
    int err = pcre2_substring_get_byname(match_data, name, &buffer, &buflen);
    if(err < 0)
    {
        PCRE2_UCHAR error_buffer[256];
        pcre2_get_error_message(err, error_buffer, sizeof(error_buffer));
        fprintf(stderr, "Error getting index %d: %s\n", err, error_buffer);
    }
    else{
        printf("%s: %.*s\n", name, (int)buflen, (char *)buffer);
    }
}

int get_substring_length(pcre2_match_data* match_data, PCRE2_SPTR name)
{
    PCRE2_SIZE buflen;
    PCRE2_UCHAR* buffer;
    int err = pcre2_substring_get_byname(match_data, name, &buffer, &buflen);
    if(err < 0) return -1;
    return buflen;
}

int get_substring(pcre2_match_data* match_data, PCRE2_SPTR name, PCRE2_UCHAR** buffer, PCRE2_SIZE* buflen)
{
    int err = pcre2_substring_get_byname(match_data, name, buffer, buflen);
    if(err < 0) return -1;
    return 0;
}

int http_parser_init() {
    int errornumber;
    PCRE2_SIZE erroroffset;
    http_message_code = pcre2_compile(http_message_pattern, PCRE2_ZERO_TERMINATED, PCRE2_DUPNAMES, &errornumber, &erroroffset, NULL);

    if (http_message_code == NULL) {
        PCRE2_UCHAR buffer[256];
        pcre2_get_error_message(errornumber, buffer, sizeof(buffer));
        fprintf(stderr, "PCRE2 compilation failed at offset %d: %s\n", (int) erroroffset,
               buffer);
        return errornumber;
    }

    http_header_code = pcre2_compile(http_header_pattern, PCRE2_ZERO_TERMINATED, PCRE2_DUPNAMES, &errornumber, &erroroffset, NULL);

    if (http_header_code == NULL) {
        PCRE2_UCHAR buffer[256];
        pcre2_get_error_message(errornumber, buffer, sizeof(buffer));
        fprintf(stderr, "PCRE2 compilation failed at offset %d: %s\n", (int) erroroffset,
                buffer);
        pcre2_code_free(http_message_code);
        return errornumber;
    }

    return 0;
}

int http_parser_parse(char* buf, size_t length, http_request* request_data)
{
    if(!http_message_code || !http_header_code) return -1;
    pcre2_match_data *message_match_data = pcre2_match_data_create_from_pattern(http_message_code, NULL);
    int rc = pcre2_match(http_message_code, (PCRE2_SPTR) buf, length, 0, 0, message_match_data, NULL);
    if(rc <= 0){
        pcre2_match_data_free(message_match_data);
        return rc;
    }

    PCRE2_SIZE buflen;
    PCRE2_UCHAR* buffer;

    get_substring(message_match_data, (PCRE2_SPTR)"method", &buffer, &buflen);
    request_data->method = (char*)buffer;
    request_data->method_length = buflen;

    get_substring(message_match_data, (PCRE2_SPTR)"request_target", &buffer, &buflen);
    request_data->target = (char*)buffer;
    request_data->target_length = buflen;

    char version_buffer[2] = {0};
    get_substring(message_match_data, (PCRE2_SPTR)"http_version_major", &buffer, &buflen);
    version_buffer[0] = (char)(buffer[0]);
    request_data->http_version.major = strtol(version_buffer, NULL, 10);

    get_substring(message_match_data, (PCRE2_SPTR)"http_version_minor", &buffer, &buflen);
    version_buffer[0] = (char)(buffer[0]);
    request_data->http_version.minor = strtol(version_buffer, NULL, 10);

    get_substring(message_match_data, (PCRE2_SPTR)"message_body", &buffer, &buflen);
    request_data->body = (char*)buffer;
    request_data->body_length = buflen;

    int offset = get_substring_length(message_match_data, (PCRE2_SPTR)"start_line") + 2;
    int data_offset = length - buflen;

    uint32_t number_of_headers = 0;
    for(int i = offset; i < data_offset - 2; i++)
    {
        //printf("%c", buf[i]);
        if(buf[i] == '\r' && buf[i+1] == '\n' && buf[i+2] != '\t')
        {
            number_of_headers++;
        }
    }

    request_data->http_headers_count = number_of_headers;
    request_data->http_headers = malloc(sizeof(http_header) * number_of_headers);
    if(request_data->http_headers == NULL) return -1000;

    int index = 0;
    while(buf[offset] != '\r')
    {
        pcre2_match_data *header_match_data = pcre2_match_data_create_from_pattern(http_header_code, NULL);
        int rca = pcre2_match(http_header_code, (PCRE2_SPTR) (buf + offset), (data_offset - offset), 0, 0, header_match_data, NULL);
        if(rca <= 0){
            pcre2_match_data_free(header_match_data);
            return rca;
        }

        get_substring(header_match_data, (PCRE2_SPTR)"field_name", &buffer, &buflen);
        request_data->http_headers[index].header_name = (char*) buffer;
        request_data->http_headers[index].header_name_length = buflen;

        get_substring(header_match_data, (PCRE2_SPTR)"field_value", &buffer, &buflen);
        request_data->http_headers[index].header_value = (char*) buffer;
        request_data->http_headers[index].header_value_length = buflen;

        PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(header_match_data);
        offset += ovector[1] - ovector[0];
        index++;
    }
    return 0;
}

void http_parser_free()
{
    pcre2_code_free(http_message_code);
    pcre2_code_free(http_header_code);
    http_message_code = NULL;
    http_header_code = NULL;
}

