#ifndef HTTPPARSER_HTTPPARSER_H
#define HTTPPARSER_HTTPPARSER_H

#include <stdint.h>

typedef struct {
    uint8_t major;
    uint8_t minor;
} http_version;

typedef struct {
    char* header_name;
    size_t header_name_length;
    char* header_value;
    size_t header_value_length;
} http_header;

typedef struct {
    http_version http_version;
    char* method;
    size_t method_length;
    char* target;
    size_t target_length;
    http_header* http_headers;
    size_t http_headers_count;
    char* body;
    size_t body_length;
} http_request;

int http_parser_init();
int http_parser_parse(char* buf, size_t length, http_request* request_data);
void http_parser_free();

void write_to_file_pattern();

#endif //HTTPPARSER_HTTPPARSER_H
