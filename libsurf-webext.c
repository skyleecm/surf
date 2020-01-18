#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>

#include <gio/gio.h>
#include <webkit2/webkit-web-extension.h>
#include <webkitdom/webkitdom.h>
#include <webkitdom/WebKitDOMDOMWindowUnstable.h>

#include "common.h"

#define LENGTH(x)   (sizeof(x) / sizeof(x[0]))

typedef struct Page {
	guint64 id;
	WebKitWebPage *webpage;
	struct Page *next;
} Page;

static int pipein, pipeout;
static Page *pages;

Page *
newpage(WebKitWebPage *page)
{
	Page *p;

	if (!(p = calloc(1, sizeof(Page))))
		die("Cannot malloc!\n");

	p->next = pages;
	pages = p;

	p->id = webkit_web_page_get_id(page);
	p->webpage = page;

	return p;
}

static void
msgsurf(Page *p, const char *s)
{
	static char msg[MSGBUFSZ];
	size_t sln = strlen(s);
	int ret;

	if ((ret = snprintf(msg, sizeof(msg), "%c%c%s",
	                    2 + sln, p ? p->id : 0, s))
	    >= sizeof(msg)) {
		fprintf(stderr, "webext: message too long: %d\n", ret);
		return;
	}

	if (pipeout && write(pipeout, msg, sizeof(msg)) < 0)
		fprintf(stderr, "webext: error sending: %.*s\n", ret-2, msg+2);
}

static gboolean
readpipe(GIOChannel *s, GIOCondition c, gpointer unused)
{
	static char msg[MSGBUFSZ], msgsz;
	WebKitDOMDOMWindow *view;
	GError *gerr = NULL;
	glong wh, ww;
	Page *p;

	if (g_io_channel_read_chars(s, msg, LENGTH(msg), NULL, &gerr) !=
	    G_IO_STATUS_NORMAL) {
		fprintf(stderr, "webext: error reading pipe: %s\n",
		        gerr->message);
		g_error_free(gerr);
		return TRUE;
	}
	if ((msgsz = msg[0]) < 3) {
		fprintf(stderr, "webext: message too short: %d\n", msgsz);
		return TRUE;
	}

	for (p = pages; p; p = p->next) {
		if (p->id == msg[1])
			break;
	}
	if (!p || !(view = webkit_dom_document_get_default_view(
	            webkit_web_page_get_dom_document(p->webpage))))
		return TRUE;

	switch (msg[2]) {
	case 'h':
		if (msgsz != 4)
			return TRUE;
		ww = webkit_dom_dom_window_get_inner_width(view);
		webkit_dom_dom_window_scroll_by(view,
		                                (ww / 100) * msg[3], 0);
		break;
	case 'v':
		if (msgsz != 4)
			return TRUE;
		wh = webkit_dom_dom_window_get_inner_height(view);
		webkit_dom_dom_window_scroll_by(view,
		                                0, (wh / 100) * msg[3]);
		break;
	}

	return TRUE;
}

// allow urireq if same main domain
gboolean
checkdomain(const char *domain,  const gchar *urireq)
{
	char dom[256];
	char reqdom[256];
	gchar *ur = strchr(urireq, ':');
	sscanf(ur, "://%[^/]", reqdom);
	char *d = strrchr(domain, '.');
	char *rd = strrchr(reqdom, '.');
	if ((d == NULL) || (rd == NULL))
		return FALSE;
	if (strcmp(d, rd) != 0)
		return FALSE;
	int len = strlen(domain) - strlen(d);
	strncpy(dom, domain, len);
	dom[len] = 0;
	*rd = 0;
	d = strrchr(dom, '.');
	rd = strrchr(reqdom, '.');
	if (d != NULL)
		d = d + 1;
	else
		d = dom;
	if (rd != NULL)
		rd = rd + 1;
	else
		rd = reqdom;
	return (strcmp(d, rd) == 0);
}

// true if page has iframe src not from the same main domain
//  skip the first iframe, otherwise lot of sites may not work, eg google login
gboolean
hasiframe(WebKitWebPage *wp, const char *domain)
{
	WebKitDOMDocument *dom = webkit_web_page_get_dom_document(wp);
	WebKitDOMNodeList *list = webkit_dom_document_get_elements_by_tag_name(dom, "iframe");
	gulong len = webkit_dom_node_list_get_length(list);
	if (len <= 1)
		return FALSE;
	int i = 0;
	for (i = 1; i < len; i++)
	{
		WebKitDOMNode *elem = webkit_dom_node_list_item(list, i);
		const gchar *src = webkit_dom_html_iframe_element_get_src(WEBKIT_DOM_HTML_IFRAME_ELEMENT(elem));
		if ((src != NULL) && !checkdomain(domain, src))
			return TRUE;
	}
	return FALSE;
}

gboolean
sendrequest(WebKitWebPage     *web_page,
               WebKitURIRequest  *request,
               WebKitURIResponse *redirected_response,
               gpointer           user_data)
{
	const gchar *uri = webkit_web_page_get_uri(web_page);
	const gchar *urireq = webkit_uri_request_get_uri(request);
	if ((strcmp(uri, urireq) == 0) || (strncmp(urireq, "data:", 5) == 0))
		return FALSE;
	if (redirected_response != NULL)
	{
		if ((webkit_uri_response_get_status_code(redirected_response) == 302) && 
			(strcmp(uri, webkit_uri_response_get_uri(redirected_response)) == 0))
			return FALSE;
	}
	char dom[256];
	gchar *u = strchr(uri, ':');
	sscanf(u, "://%[^/]", dom);
	if (!hasiframe(web_page, dom))
		return FALSE;
	// suppress request if not from same source, and hasiframe is true
	return !checkdomain(dom, urireq);
}

static void
webpagecreated(WebKitWebExtension *e, WebKitWebPage *wp, gpointer unused)
{
	Page *p = newpage(wp);
	g_signal_connect(wp, "send-request", G_CALLBACK(sendrequest), NULL);
}

G_MODULE_EXPORT void
webkit_web_extension_initialize_with_user_data(WebKitWebExtension *e, GVariant *gv)
{
	GIOChannel *gchanpipe;

	g_signal_connect(e, "page-created", G_CALLBACK(webpagecreated), NULL);

	g_variant_get(gv, "(ii)", &pipein, &pipeout);
	msgsurf(NULL, "i");

	gchanpipe = g_io_channel_unix_new(pipein);
	g_io_channel_set_encoding(gchanpipe, NULL, NULL);
	g_io_channel_set_close_on_unref(gchanpipe, TRUE);
	g_io_add_watch(gchanpipe, G_IO_IN, readpipe, NULL);
}
