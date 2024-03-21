#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <asm-generic/socket.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/sha.h>

#define WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define WS_REQUEST_KEY_LENGTH 24
#define SHA_DIGEST_LENGTH 20

#define BYTE_TO_BINARY_PATTERN "%c%c%c%c%c%c%c%c"
#define BYTE_TO_BINARY(byte)  \
  ((byte) & 0x80 ? '1' : '0'), \
  ((byte) & 0x40 ? '1' : '0'), \
  ((byte) & 0x20 ? '1' : '0'), \
  ((byte) & 0x10 ? '1' : '0'), \
  ((byte) & 0x08 ? '1' : '0'), \
  ((byte) & 0x04 ? '1' : '0'), \
  ((byte) & 0x02 ? '1' : '0'), \
  ((byte) & 0x01 ? '1' : '0')

int get_header_value(const char *request, const char *header, char *dest, size_t dest_size);

int base64_encode(const uint8_t *input, size_t input_size, char *dest, size_t dest_size);

int ws_make_handshake_response(const char *request, char *dest, size_t dest_size);
int ws_get_frame_text(const uint8_t *frame, char *dest, size_t dest_size);

int main() {

	char html_response[] = "HTTP/1.1 200 OK\r\n\r\n<html><head></head><body><h1>Hello World</h1></body></html>";
	/* char response_data[] = "HTTP/1.1 200 OK\r\n\r\n"; */

	int server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (server_socket == -1) {
		perror("Failed to create server socket");
		return 1;
	}

	int setsockopt_status = setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

	if (setsockopt_status == -1) {
		perror("Failed to set SO_REUSEADDR on server socket");
		close(server_socket);
		return 1;
	}

	struct sockaddr_in listen_address = {
		.sin_family = AF_INET,
		.sin_port = htons(8080),
		.sin_addr = {
			.s_addr = htons(INADDR_ANY)
		}
	};

	int bind_status = bind(server_socket, (struct sockaddr*)&listen_address, sizeof(listen_address));

	if (bind_status == -1) {
		perror("Failed to bind listen address to server socket");
		close(server_socket);
		return 1;
	}

	int listen_status = listen(server_socket, 10);

	if (listen_status == -1) {
		perror("Failed to set server socket to listen");
		close(server_socket);
		return 1;
	}

	int client_socket;
	char request_buffer[4096];

	while (1) {
		client_socket = accept(server_socket, NULL, NULL);

		if (client_socket == -1) {
			perror("Failed to accept incoming request");
			continue;
		}

		int recv_status = recv(client_socket, &request_buffer, sizeof(request_buffer), 0);

		if (recv_status == -1) {
			perror("Failed to receive message from client socket");
			close(client_socket);
			continue;
		}

		/* printf("Request:\n%s\n", request_buffer); */

		if (strstr(request_buffer, "Upgrade: websocket") != NULL) {

			printf("\nWebsocket handshake\n");
			fflush(stdout);

			char ws_handshake_response[256];

			int status = ws_make_handshake_response(request_buffer, ws_handshake_response, sizeof(ws_handshake_response));

			if (status == -1) {
				fprintf(stderr, "Failed to create handshake response.\n");
				fflush(stderr);
				close(client_socket);
				continue;
			}

			int send_status = send(client_socket, ws_handshake_response, strlen(ws_handshake_response), 0);

			if (send_status == -1) {
				perror("Failed to send message to client socket");
			}

			printf("WebSocket handshake response sent.\n");
			fflush(stdout);

			while (1) {
				uint8_t ws_frame[512];

				int recv_status = recv(client_socket, ws_frame, sizeof(ws_frame), 0);

				if (recv_status == -1) {
					perror("Failed to receive frame from client socket");
					break;
				}

				if ((*ws_frame & 0b00001111) == 8) { // close connection
					break;
				}

				char ws_frame_text[499]; // 512(frame size) - 14(max no-payload size) + 1('\0')

				int frame_status = ws_get_frame_text(ws_frame, ws_frame_text, sizeof(ws_frame_text));

				if (frame_status == -1) {
					fprintf(stderr, "Failed to get text from client frame.\n");
					fflush(stderr);
					break;
				}

				printf("////\n%s\n////\n", ws_frame_text);
				fflush(stdout);
			}

			close(client_socket);
			continue;
		}

		printf("\nResource request\n");
		fflush(stdout);

		int send_status = send(client_socket, html_response, sizeof(html_response) - 1, 0);

		if (send_status == -1) {
			perror("Failed to send message to client socket");
		}

		printf("Response sent.\n\n");
		fflush(stdout);

		close(client_socket);
	}

	return 0;
}

int ws_get_frame_text(const uint8_t *frame, char *dest, size_t dest_size) {
	// https://datatracker.ietf.org/doc/html/rfc6455#section-5.2

	uint64_t payload_length = frame[1] & 0b01111111;
	uint8_t extended_payload_size = 0;

	if (payload_length == 126) {
		payload_length = ntohs(*(uint16_t *)(frame + 2));
		extended_payload_size = 2;

	} else if (payload_length == 127) {
		payload_length = ntohl(*(uint64_t *)(frame + 2));
		extended_payload_size = 8;
	}

	const uint8_t *mask = frame + 2 + extended_payload_size;
	uint8_t mask_index = 0; // % 4

	for (uint64_t i = 0; i < payload_length; ++i) {

		if (i > dest_size - 2) {
			return -1;
		}

		*dest = *(frame + 2 + extended_payload_size + 4 + i) ^ mask[mask_index];

		dest++;
		mask_index = (mask_index + 1) % 4;
	}

	*dest = 0;

	return 0;
}

int ws_make_handshake_response(const char *request, char *dest, size_t dest_size) {

	char request_key[64];

	int status = get_header_value(request, "Sec-WebSocket-Key", request_key, sizeof(request_key) - sizeof(WS_GUID) + 1);

	if (status == -1) {
		fprintf(stderr, "Failed to get header value.\n");
		fflush(stderr);
		return -1;
	}

	strcat(request_key, WS_GUID);

	uint8_t accept_hash[SHA_DIGEST_LENGTH];

	SHA1((unsigned char *)request_key, strlen(request_key), accept_hash);

	char accept_header[64] = "Sec-WebSocket-Accept: ";

	status = base64_encode(
		accept_hash,
		sizeof(accept_hash),
		accept_header + sizeof("Sec-WebSocket-Accept: ") - 1,
		sizeof(accept_header) - sizeof("Sec-WebSocket-Accept: \r\n") + 1
	);

	if (status == -1) {
		fprintf(stderr, "Failed to base64 encode websocket handshake accept hash.\n");
		fflush(stderr);
		return -1;
	}

	strcat(accept_header, "\r\n");

	char handshake_response[] =
		"HTTP/1.1 101 Switching Protocols\r\n"
		"Upgrade: websocket\r\n"
		"Connection: Upgrade\r\n"
		"Origin: localhost:8080\r\n"
		"Sec-WebSocket-Version: 13\r\n";

	if (dest_size < sizeof(handshake_response) + sizeof(accept_header) + sizeof("\r\n") - 2) { // 2 = '\0'
		return -1;
	}

	dest = strncpy(dest, handshake_response, sizeof(dest_size));

	dest = strcat(dest, accept_header);

	strcat(dest, "\r\n");

	return 0;
}

int get_header_value(const char *request, const char *header, char *dest, size_t dest_size) {

	char *header_pos = strstr(request, header);

	if (header_pos == NULL) {
		return -1;
	}

	header_pos += strlen(header) + 2; // 2 = ": "

	while (*header_pos != '\r') {

		if (*header_pos == 0 || dest_size == 0) {
			return -1;
		}

		*dest = *header_pos;
		header_pos++;
		dest++;
		dest_size--;
	}

	if (dest_size == 0) {
		return -1;
	}

	*dest = '\0';

	return 0;
}

int base64_encode(const uint8_t *input, size_t input_size, char *dest, size_t dest_size) {

	static const unsigned char base64_characters[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	uint8_t input_buff[3] = {0, 0, 0};

	while (input_size) {

		input_buff[0] = *input;
		input++;
		input_size--;

		if (input_size) {
			input_buff[1] = *input;
			input++;
			input_size--;
		} else {
			input_buff[1] = 0;
		}

		if (input_size) {
			input_buff[2] = *input;
			input++;
			input_size--;
		} else {
			input_buff[2] = 0;
		}

        dest_size -= 4;

        if (dest_size <= 0) {
            return -1;
        }

		*dest = base64_characters[ input_buff[0] >> 2 ];
		dest++;

		*dest = base64_characters[ ((input_buff[0] & 0b00000011) << 4) | (input_buff[1] >> 4) ];
		dest++;

		if (input_buff[1] == 0) {
			*dest = '=';
			dest++;
			*dest = '=';
			dest++;
			continue;
		}

		*dest = base64_characters[ ((input_buff[1] & 0b00001111) << 2) | (input_buff[2] >> 6) ];
		dest++;

		if (input_buff[2] == 0) {
			*dest = '=';
			dest++;
			continue;
		}

		*dest = base64_characters[ input_buff[2] & 0b00111111 ];
		dest++;
	}

	*dest = 0;

	return 0;
}
