
#include <curl/curl.h>
#include <libxml/xmlreader.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>
#include "zuo.h"

static zuo_ext_t *sc_curl_easy_init(zuo_ext_t *args) {
  CURL *curl_handle;
  curl_handle = curl_easy_init();
  return zuo_ext_foreign((void*)curl_handle);
}

static zuo_ext_t *sc_curl_easy_cleanup(zuo_ext_t *args) {
  curl_easy_cleanup(zuo_ext_foreign_deref(zuo_ext_car(args)));
  return zuo_ext_void();
}

size_t sc_curl_fetch_cb(void *buf, size_t size, size_t count, void *data) {
  zuo_ext_t **d;
  zuo_ext_t *s;

  d = (zuo_ext_t**) data;
  zuo_ext_stash_push(*d);
  s = zuo_ext_string(buf, size * count);
  zuo_ext_stash_push(s);
  *d = zuo_ext_cons(s, *d);
  zuo_ext_stash_pop();
  zuo_ext_stash_pop();
  return (count * size);
}

zuo_ext_t *sc_curl_strerror(CURLcode errno) {
  const char *s = curl_easy_strerror(errno);
  return zuo_ext_string(s, strlen(s));
}

static zuo_ext_t *sc_curl_fetch(zuo_ext_t *args) {
  CURL *c;
  char *url;
  CURLcode ret;
  zuo_ext_t *blist;

  c = zuo_ext_foreign_deref(zuo_ext_car(args));
  url = zuo_ext_string_ptr(zuo_ext_car(zuo_ext_cdr(args)));

  ret = curl_easy_setopt(c, CURLOPT_URL, url);
  if (ret != CURLE_OK)
    return sc_curl_strerror(ret);

  ret = curl_easy_setopt(c, CURLOPT_VERBOSE, 1);
  if (ret != CURLE_OK)
    return sc_curl_strerror(ret);

  ret = curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, sc_curl_fetch_cb);
  if (ret != CURLE_OK)
    return sc_curl_strerror(ret);

  blist = zuo_ext_null();
  ret = curl_easy_setopt(c, CURLOPT_WRITEDATA, &blist);
  if (ret != CURLE_OK)
    return sc_curl_strerror(ret);

  ret = curl_easy_perform(c);
  if (ret != CURLE_OK)
    return sc_curl_strerror(ret);

  return blist;
}

static zuo_ext_t *sc_xml_make_reader(zuo_ext_t *args) {
  xmlTextReaderPtr reader;
  zuo_ext_t *doc, *url;
  doc = zuo_ext_car(args);
  url = zuo_ext_car(zuo_ext_cdr(args));
  reader = xmlReaderForMemory(zuo_ext_string_ptr(doc),
                              zuo_ext_string_length(doc),
                              zuo_ext_string_ptr(url),
                              NULL, 0);
  if (reader != NULL)
    return zuo_ext_foreign((void*)reader);
  return zuo_ext_false();
}

static zuo_ext_t *sc_xml_free_reader(zuo_ext_t *args) {
  xmlFreeTextReader((xmlTextReaderPtr)zuo_ext_foreign_deref(zuo_ext_car(args)));
  return zuo_ext_void();
}

static zuo_ext_t *sc_xml_read(zuo_ext_t *args) {
  xmlTextReaderPtr reader = (xmlTextReaderPtr) zuo_ext_foreign_deref(zuo_ext_car(args));
  return zuo_ext_integer(xmlTextReaderRead(reader));
}

static zuo_ext_t *sc_xml_depth(zuo_ext_t *args) {
  xmlTextReaderPtr reader = (xmlTextReaderPtr) zuo_ext_foreign_deref(zuo_ext_car(args));
  return zuo_ext_integer(xmlTextReaderDepth(reader));
}

static zuo_ext_t *sc_xml_nodetype(zuo_ext_t *args) {
  xmlTextReaderPtr reader = (xmlTextReaderPtr) zuo_ext_foreign_deref(zuo_ext_car(args));
  return zuo_ext_integer(xmlTextReaderNodeType(reader));
}

zuo_ext_t *sc_string_xml_to_zuo(xmlChar* s) {
  zuo_ext_t *ret = zuo_ext_string(s, xmlStrlen(s));
  xmlFree(s);
  return ret;
}

static zuo_ext_t *sc_xml_name(zuo_ext_t *args) {
  xmlTextReaderPtr reader = (xmlTextReaderPtr) zuo_ext_foreign_deref(zuo_ext_car(args));
  xmlChar *name;
  zuo_ext_t *ret;

  name = xmlTextReaderName(reader);
  if (name != NULL) {
    ret = sc_string_xml_to_zuo(name);
  } else {
    ret = zuo_ext_false();
  }

  return ret;
}

static zuo_ext_t *sc_xml_attribute(zuo_ext_t *args) {
  xmlTextReaderPtr reader = (xmlTextReaderPtr) zuo_ext_foreign_deref(zuo_ext_car(args));
  xmlChar *attr_val;
  zuo_ext_t *attr_name, *ret;

  attr_name = zuo_ext_car(zuo_ext_cdr(args));
  attr_val = xmlTextReaderGetAttribute(reader, zuo_ext_string_ptr(attr_name));
  if (attr_val != NULL) {
    ret = sc_string_xml_to_zuo(attr_val);
  } else {
    ret = zuo_ext_false();
  }

  return ret;
}

static zuo_ext_t *sc_sha1(zuo_ext_t *args) {
  zuo_ext_t *input, *ret;
  char digest[20], hex_digest[40];

  input = zuo_ext_car(args);
  SHA1(zuo_ext_string_ptr(input), zuo_ext_string_length(input), digest);
  for (int i = 0; i < 20; i++) {
    snprintf(&hex_digest[i * 2], 3, "%02x", digest[i]);
  }
  return zuo_ext_string(hex_digest, 40);
}

int main() {
  zuo_ext_t *mod_ht, *lib_path, *mod_name;

  /* Step 1 */
  zuo_ext_primitive_init();

  zuo_ext_add_primitive(sc_curl_easy_init, 1 << 0, "curl-easy-init");
  zuo_ext_add_primitive(sc_curl_easy_cleanup, 1 << 1, "curl-easy-cleanup");
  zuo_ext_add_primitive(sc_curl_fetch, 1 << 2, "curl-fetch*");

  zuo_ext_add_primitive(sc_xml_make_reader, 1 << 2, "xml-make-reader");
  zuo_ext_add_primitive(sc_xml_free_reader, 1 << 1, "xml-free-reader");
  zuo_ext_add_primitive(sc_xml_read, 1 << 1, "xml-read");
  zuo_ext_add_primitive(sc_xml_depth, 1 << 1, "xml-depth");
  zuo_ext_add_primitive(sc_xml_nodetype, 1 << 1, "xml-nodetype");
  zuo_ext_add_primitive(sc_xml_name, 1 << 1, "xml-name");
  zuo_ext_add_primitive(sc_xml_attribute, 1 << 2, "xml-attribute");
  zuo_ext_add_primitive(sc_sha1, 1 << 1, "sha1");

  /* Step 2 */
  zuo_ext_image_init(NULL);

  /* Step 3 */
  lib_path = zuo_ext_string("lib", 3);
  // zuo_ext_runtime_init(zuo_ext_false(), zuo_ext_empty_hash());
  zuo_ext_runtime_init(lib_path, zuo_ext_empty_hash());

  if (0) {
    const char *dump = "#lang zuo/kernel (dump-image-and-exit (fd-open-output \"image\"))";
    (void)zuo_ext_eval_module(zuo_ext_symbol("dump"), dump, strlen(dump));
    /* Afterward, use
          zuo local/image.zuo --image image
       to generate a ".c" file to link with this example. */
  }

  curl_global_init(CURL_GLOBAL_ALL);

  /* Run `prog`: */
  // ht = zuo_ext_eval_module(zuo_ext_symbol("five-app"), prog, strlen(prog));
  mod_name = zuo_ext_symbol("example-app");
  mod_ht = zuo_ext_apply(zuo_ext_hash_ref(zuo_ext_kernel_env(),
                                          zuo_ext_symbol("module->hash"),
                                          zuo_ext_false()),
                         zuo_ext_cons(mod_name, zuo_ext_null()));

  /* Inspect the result: */
  /*
  v = zuo_ext_hash_ref(ht, zuo_ext_symbol("number"), zuo_ext_false());
  if (zuo_ext_apply(zuo_ext_hash_ref(zuo_ext_kernel_env(),
                                     zuo_ext_symbol("integer?"),
                                     zuo_ext_false()),
                    zuo_ext_cons(v, zuo_ext_null()))
      == zuo_ext_true())
    printf("The answer was %d\n", (int)zuo_ext_integer_value(v));
  else
    printf("Something went wrong!\n");
  */

  return 0;
}
