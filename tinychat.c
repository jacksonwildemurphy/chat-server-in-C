/*
 * tinychat.c - [Starting code for] a web-based chat server.
 *
 * Based on:
 *  tiny.c - A simple, iterative HTTP/1.0 Web server that uses the
 *      GET method to serve static and dynamic content.
 *   Tiny Web server
 *   Dave O'Hallaron
 *   Carnegie Mellon University
 */
#include "csapp.h"
#include "dictionary.h"
#include "more_string.h"

void doit(int fd);
dictionary_t *read_requesthdrs(rio_t *rp);
void read_postquery(rio_t *rp, dictionary_t *headers, dictionary_t *d);
void parse_query(const char *uri, dictionary_t *d);
void serve_form(int fd, dictionary_t* query, dictionary_t* topics);
void serve_login(int fd, dictionary_t* query);
void serve_topic_conversation(int fd, dictionary_t* query, dictionary_t* topics);
void add_conversation_content(int fd, dictionary_t* query, dictionary_t* topics);
void clienterror(int fd, char *cause, char *errnum,
		 char *shortmsg, char *longmsg);
static void print_stringdictionary(dictionary_t *d);

/* Holds the conversations of each topic */
static dictionary_t* topics;

int main(int argc, char **argv)
{
  int listenfd, connfd;
  char hostname[MAXLINE], port[MAXLINE];
  socklen_t clientlen;
  struct sockaddr_storage clientaddr;

  /* Check command line args */
  if (argc != 2) {
    fprintf(stderr, "usage: %s <port>\n", argv[0]);
    exit(1);
  }

  listenfd = Open_listenfd(argv[1]);

  /* Don't kill the server if there's an error, because
     we want to survive errors due to a client. But we
     do want to report errors. */
  exit_on_error(0);

  /* Also, don't stop on broken connections: */
  Signal(SIGPIPE, SIG_IGN);

	/* Keep the conversations of each topic in memory */
	topics = make_dictionary(COMPARE_CASE_SENS, free);


  while (1) {
    clientlen = sizeof(clientaddr);
    connfd = Accept(listenfd, (SA *)&clientaddr, &clientlen);
    if (connfd >= 0) {
      Getnameinfo((SA *) &clientaddr, clientlen, hostname, MAXLINE,
                  port, MAXLINE, 0);
      printf("Accepted connection from (%s, %s)\n", hostname, port);
      doit(connfd);
      Close(connfd);
    }
  }
}

/*
 * doit - handle one HTTP request/response transaction
 */
void doit(int fd)
{
  char buf[MAXLINE], *method, *uri, *version;
  rio_t rio;
  dictionary_t *headers, *query;

  /* Read request line and headers */
  Rio_readinitb(&rio, fd);
  if (Rio_readlineb(&rio, buf, MAXLINE) <= 0)
    return;
  printf("%s", buf);

  if (!parse_request_line(buf, &method, &uri, &version)) {
    clienterror(fd, method, "400", "Bad Request",
                "TinyChat did not recognize the request");
  } else {
    if (strcasecmp(version, "HTTP/1.0")
        && strcasecmp(version, "HTTP/1.1")) {
      clienterror(fd, version, "501", "Not Implemented",
                  "TinyChat does not implement that version");
    } else if (strcasecmp(method, "GET")
               && strcasecmp(method, "POST")) {
      clienterror(fd, method, "501", "Not Implemented",
                  "TinyChat does not implement that method");
    } else {
			printf("\nuri is %s\n\n", uri);


      headers = read_requesthdrs(&rio);

      /* Parse all query arguments into a dictionary */
      query = make_dictionary(COMPARE_CASE_SENS, free);
      parse_uriquery(uri, query);
      if (!strcasecmp(method, "POST")){
        read_postquery(&rio, headers, query);
				char* content = dictionary_get(query, "content");
				printf("content is %s\n", content);
				/* Serve either a login form or a chat room form: */
				if(starts_with("/reply", uri))
				serve_form(fd, query, topics);

			}
			else{ // Request was a GET

				if(starts_with("/conversation?topic=", uri))
					serve_topic_conversation(fd, query, topics);
				else if(starts_with("/say?user=", uri))
					add_conversation_content(fd, query, topics);
				else
					serve_login(fd, query);

			}
      /* For debugging, print the dictionary */
      print_stringdictionary(query);


      /* Clean up */
      free_dictionary(query);
      free_dictionary(headers);
    }

    /* Clean up status line */
    free(method);
    free(uri);
    free(version);
  }
}

/*
 * read_requesthdrs - read HTTP request headers
 */
dictionary_t *read_requesthdrs(rio_t *rp)
{
  char buf[MAXLINE];
  dictionary_t *d = make_dictionary(COMPARE_CASE_INSENS, free);

  Rio_readlineb(rp, buf, MAXLINE);
  printf("%s", buf);
  while(strcmp(buf, "\r\n")) {
    Rio_readlineb(rp, buf, MAXLINE);
    printf("%s", buf);
    parse_header_line(buf, d);
  }

  return d;
}

void read_postquery(rio_t *rp, dictionary_t *headers, dictionary_t *dest)
{
  char *len_str, *type, *buffer;
  int len;

  len_str = dictionary_get(headers, "Content-Length");
  len = (len_str ? atoi(len_str) : 0);

  type = dictionary_get(headers, "Content-Type");

  buffer = malloc(len+1);
  Rio_readnb(rp, buffer, len);
  buffer[len] = 0;

  if (!strcasecmp(type, "application/x-www-form-urlencoded")) {
    parse_query(buffer, dest);
  }

  free(buffer);
}

static char *ok_header(size_t len, const char *content_type) {
  char *len_str, *header;

  header = append_strings("HTTP/1.0 200 OK\r\n",
                          "Server: TinyChat Web Server\r\n",
                          "Connection: close\r\n",
                          "Content-length: ", len_str = to_string(len), "\r\n",
                          "Content-type: ", content_type, "\r\n\r\n",
                          NULL);
  free(len_str);

  return header;
}

/* Adds the given content to the specified topic as the specified user.
	Returns a successful html response header but nothing else if the parameters
	were legal. Otherwise returns an error header*/
void add_conversation_content(int fd, dictionary_t* query, dictionary_t* topics)
{
	if(dictionary_count(query) != 3){
		clienterror(fd, "Bad query format", "400",
				 "Bad Request", "Expected format of /say?user=<user>&topic=<topic>&content=<content>");
		return;
	}

	size_t len;
  char *body, *header;

  char* user = dictionary_get(query, "user");
	char* topic = dictionary_get(query, "topic");
	char* new_post = dictionary_get(query, "content");
	char* history = dictionary_get(topics, topic);

  if(user == NULL || !strcmp(user, "")){
		user = "Anonymous";
	}
	if(history == NULL)
    history = "";

	if(new_post == NULL || strlen(new_post) == 0)
		new_post = "";

	new_post = append_strings(user, ": ", new_post, "\r\n", NULL);
	history = append_strings(history, new_post, NULL);
	dictionary_set(topics, topic, history);


	body = "Your content was added to the conversation.\r\n";
	len = strlen(body);

  /* Send response headers to client */
  header = ok_header(len, "text/plain; charset=utf-8");
  Rio_writen(fd, header, strlen(header));
  printf("Response headers:\n");
  printf("%s", header);

  free(header);

  /* Send response body to client */
  Rio_writen(fd, body, len);
}


/*
 * Returns the conversation content of a given topic in plaintext
 */
void serve_topic_conversation(int fd, dictionary_t* query, dictionary_t* topics)
{
	char* topic = dictionary_get(query, "topic");
	char* conversation = dictionary_get(topics, topic);
	char *body, *header;

	// If the topic doesn't exist, send back an empty response body
	if(conversation == NULL)
		body = "";

	// Return the topic's conversation content as plaintext
	else{
		body = conversation;
	}

	size_t len = strlen(body);

  /* Send response headers to client */
  header = ok_header(len, "text/plain; charset=utf-8");
  Rio_writen(fd, header, strlen(header));
  printf("Response headers:\n");
  printf("%s", header);

  free(header);

  /* Send response body to client */
  Rio_writen(fd, body, len);
}


/*
 * serve_form - sends a form to a client
 */
void serve_form(int fd, dictionary_t* query, dictionary_t* topics)
{
  size_t len;
  char *body, *header;

  char* user = dictionary_get(query, "user");
	char* topic = dictionary_get(query, "topic");
	char* new_post = dictionary_get(query, "content");
	char* history = dictionary_get(topics, topic);

  if(user == NULL || !strcmp(user, "")){
		user = "Anonymous";
	}
	if(history == NULL)
    history = "";

	if(new_post == NULL || strlen(new_post) == 0)
		new_post = "";
  else {
		new_post = append_strings(user, ": ", new_post, "\r\n", NULL);
		history = append_strings(history, new_post, NULL);
		dictionary_set(topics, topic, history);
	}

  body = append_strings("<html><body>\r\n",
                        "<p>Welcome to TinyChat, ",
			user,"</p>",
			"<p>Topic: ",topic,"</p>",
			"<textarea readonly rows=\"10\" cols=\"60\">",history, "</textarea>",
                        "\r\n<form action=\"reply\" method=\"post\"",
                        " enctype=\"application/x-www-form-urlencoded\"",
                        " accept-charset=\"UTF-8\">\r\n",
												"<input type=\"hidden\" name=\"user\" value=\"", user, "\">\r\n",
												"<input type=\"hidden\" name=\"topic\" value=\"", topic, "\">\r\n",
												user, ": ",
                        "<input type=\"text\" name=\"content\">\r\n",
                        "<input type=\"submit\" value=\"Send\">\r\n",
                        "</form></body></html>\r\n",
                        NULL);

  len = strlen(body);

  /* Send response headers to client */
  header = ok_header(len, "text/html; charset=utf-8");
  Rio_writen(fd, header, strlen(header));
  printf("Response headers:\n");
  printf("%s", header);

  free(header);

  /* Send response body to client */
  Rio_writen(fd, body, len);

  free(body);
}

/*
 * serve_login - sends a login form to a client
 */
void serve_login(int fd, dictionary_t* query)
{
  size_t len;
  char *body, *header;

	body = append_strings("<html><body>\r\n",
                      "<p>Welcome to TinyChat, please log in</p>",
                      "\r\n<form action=\"reply\" method=\"post\"",
                      " enctype=\"application/x-www-form-urlencoded\"",
                      " accept-charset=\"UTF-8\">\r\n",
											"Name: <input type=\"text\" name=\"user\"><br><br>\r\n",
											"Topic: <input type=\"text\" name=\"topic\"><br><br>\r\n",
											"<input type=\"submit\" value=\"Join Conversation\">\r\n",
                      "</form></body></html>\r\n",
                      NULL);

  len = strlen(body);

  /* Send response headers to client */
  header = ok_header(len, "text/html; charset=utf-8");
  Rio_writen(fd, header, strlen(header));
  printf("Response headers:\n");
  printf("%s", header);

  free(header);

  /* Send response body to client */
  Rio_writen(fd, body, len);

  free(body);
}

/*
 * clienterror - returns an error message to the client
 */
void clienterror(int fd, char *cause, char *errnum,
		 char *shortmsg, char *longmsg)
{
  size_t len;
  char *header, *body, *len_str;

  body = append_strings("<html><title>Tiny Error</title>",
                        "<body bgcolor=""ffffff"">\r\n",
                        errnum, " ", shortmsg,
                        "<p>", longmsg, ": ", cause,
                        "<hr><em>The Tiny Web server</em>\r\n",
                        NULL);
  len = strlen(body);

  /* Print the HTTP response */
  header = append_strings("HTTP/1.0 ", errnum, " ", shortmsg,
                          "Content-type: text/html; charset=utf-8\r\n",
                          "Content-length: ", len_str = to_string(len), "\r\n\r\n",
                          NULL);
  free(len_str);

  Rio_writen(fd, header, strlen(header));
  Rio_writen(fd, body, len);

  free(header);
  free(body);
}

static void print_stringdictionary(dictionary_t *d)
{
  int i, count;

  count = dictionary_count(d);
  for (i = 0; i < count; i++) {
    printf("%s=%s\n",
           dictionary_key(d, i),
           (const char *)dictionary_value(d, i));
  }
  printf("\n");
}
