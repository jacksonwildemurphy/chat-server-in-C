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
#include <unistd.h>
#include "csapp.h"
#include "dictionary.h"
#include "more_string.h"
#include <pthread.h>


void* doit(void* fd_p);
dictionary_t *read_requesthdrs(rio_t *rp);
void read_postquery(rio_t *rp, dictionary_t *headers, dictionary_t *d);
void parse_query(const char *uri, dictionary_t *d);
void serve_form(int fd, dictionary_t* query, dictionary_t* topics);
void serve_login(int fd, dictionary_t* query);
void serve_topic_conversation(int fd, dictionary_t* query, dictionary_t* topics);
void add_conversation_content(int fd, dictionary_t* query, dictionary_t* topics, int internal_request);
void import_topic_content(int fd, dictionary_t* query, dictionary_t* topics);
void clienterror(int fd, char *cause, char *errnum,
		 char *shortmsg, char *longmsg);
static void dictionary_change_topic(char* topic, char* content);
static void print_stringdictionary(dictionary_t *d);

/* Holds the conversations of each topic */
static dictionary_t* topics;

/* Semaphore lock for safe concurrent handling of client requests*/
static sem_t lock;

static char* serverport;


int main(int argc, char **argv)
{
  int listenfd, *connfd_p;
  char hostname[MAXLINE], port[MAXLINE];
  socklen_t clientlen;
  struct sockaddr_storage clientaddr;
	pthread_t tid;
	Sem_init(&lock, 0, 1);
	serverport = argv[1];

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
		connfd_p = malloc(sizeof(int));
    *connfd_p = Accept(listenfd, (SA *)&clientaddr, &clientlen);
    if (*connfd_p >= 0) {
      Getnameinfo((SA *) &clientaddr, clientlen, hostname, MAXLINE,
                  port, MAXLINE, 0);
      printf("Accepted connection from (%s, %s)\n", hostname, port);
			Pthread_create(&tid, NULL, doit, connfd_p);
			Pthread_detach(tid);
    }
  }
}

/*
 * doit - handle one HTTP request/response transaction
 */
void* doit(void* fd_p)
{
	int fd = *((int*)fd_p);
  char buf[MAXLINE], *method, *uri, *version;
  rio_t rio;
  dictionary_t *headers, *query;

  /* Read request line and headers */
  Rio_readinitb(&rio, fd);
  if (Rio_readlineb(&rio, buf, MAXLINE) <= 0)
    return NULL;
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
					add_conversation_content(fd, query, topics, 0);
				else if(starts_with("/import?topic=", uri))
					import_topic_content(fd, query, topics);
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

	free(fd_p);

	/* Close the connection */
	Close(fd);
	return NULL;
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


/* Handles the get request to /import?topic=<topic>&host=<host>&port=<port>
	Contacts the given conversation server to get its conversation content for <topic>.
	That content is appended to the servers own content for that topic.
*/
void import_topic_content(int fd, dictionary_t* query, dictionary_t* topics)
{
	if(dictionary_count(query) != 3){
		clienterror(fd, "Bad query format", "400",
				 "Bad Request", "Expected format of /import?topic=<topic>&host=<host>&port=<port>");
		return;
	}

	char* topic = dictionary_get(query, "topic");
	char* history = dictionary_get(topics, topic);
	char* host = dictionary_get(query, "host");
	char* port = dictionary_get(query, "port");

	// If host and port number are for this server, just make a copy of the topic and append it to itself
	if(!strcasecmp("localhost", host) && !strcasecmp(serverport, port)){
		printf("server and client are the same\n");
		char* contents = append_strings(dictionary_get(topics, topic), NULL);
		dictionary_set(query, "content", contents);
		add_conversation_content(fd, query, topics, 1);
		return;
	}

	char* req_header = append_strings("GET /conversation?topic=", topic, " HTTP/1.1\r\n\r\n", NULL);

	// Try to connect with specified host
	int clientfd;
	rio_t rio;
	clientfd = Open_clientfd(host, port);
	Rio_readinitb(&rio, clientfd);
	Rio_writen(clientfd, req_header, strlen(req_header));
	char buf[MAXBUF];
	char* response = malloc(sizeof(char));
	// used to free memory during repeated appending of server response lines to 'response'
	char* old_response;
	Rio_readlineb(&rio, buf, MAXBUF);
	printf("Import server response status was: %s\n", buf );

	// Tell the client if there was a problem connecting to the specified host and port
	if((!starts_with("HTTP/1.0 200 OK", buf) && !starts_with("HTTP/1.0 200 OK", buf))){
		clienterror(fd, "Bad query format", "400",
			 "Bad Request", "The host and port you supplied don't seem to be for a chat server");
	free(req_header);
	return;
	}

	// Our connection with the specified host and port was successful
	while(strcmp(buf, "\r\n")) // Consume the headers
		Rio_readlineb(&rio, buf, MAXBUF);

	printf("Out of the while loop. Response body: \n");
	while(Rio_readlineb(&rio, buf, MAXBUF)){
		old_response = response;
		response = append_strings(response, buf, NULL);
		free(old_response);
	}
	printf("%s\n", response);
	Close(clientfd);

	// Topic content is now in "response". Appended to this server's history
	if(history == NULL)
		history = "";

	if(response == NULL || strlen(response) == 0)
		response = "";

	history = append_strings(history, response, NULL);
	dictionary_change_topic(topic, history);
	free(response);

	char* body = "The conversation was successfully imported.\r\n";
	size_t len = strlen(body);

  /* Send response headers to client */
  char* header = ok_header(len, "text/plain; charset=utf-8");
  Rio_writen(fd, header, strlen(header));
  printf("Response headers:\n");
  printf("%s", header);

  free(header);

  /* Send response body to client */
  Rio_writen(fd, body, len);
}



/* Adds the given content to the specified topic as the specified user.
	Returns a successful html response header but nothing else if the parameters
	were legal. Otherwise returns an error header*/
void add_conversation_content(int fd, dictionary_t* query, dictionary_t* topics, int internal_request)
{
	if(internal_request == 0){
		if(dictionary_count(query) != 3){
			clienterror(fd, "Bad query format", "400",
					 "Bad Request", "Expected format of /say?user=<user>&topic=<topic>&content=<content>");
			return;
		}
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
	dictionary_change_topic(topic, history);
	free(new_post);


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
		dictionary_change_topic(topic, history);
		free(new_post);
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

static void dictionary_change_topic(char* topic, char* content){
	P(&lock);
	dictionary_set(topics, topic, content);
	V(&lock);
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
