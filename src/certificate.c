#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/x509.h>

#include "Python.h"
#include "structmember.h"

#define MAX_BUF 256

typedef struct {
	PyObject_HEAD;
	X509 *x509;
} certificate_x509;

static void
certificate_x509_dealloc(certificate_x509 *self) {
	X509_free(self->x509);
	self->ob_type->tp_free((PyObject *)self);
}

static PyObject *get_not_before(certificate_x509 *self, PyObject *varargs);
static PyObject *get_not_after(certificate_x509 *self, PyObject *varargs);
static PyObject *get_serial_number(certificate_x509 *self, PyObject *varargs);
static PyObject *get_subject(certificate_x509 *self, PyObject *varargs);
static PyObject *get_extension(certificate_x509 *self, PyObject *varargs, PyObject *keywords);
static PyObject *get_all_extensions(certificate_x509 *self, PyObject *varargs);

static PyMethodDef x509_methods[] = {
	{"get_not_before", get_not_before, METH_VARARGS,
	 "get the certificate's start time"},
	{"get_not_after", get_not_after, METH_VARARGS,
	 "get the certificate's end time"},
	{"get_serial_number", get_serial_number, METH_VARARGS,
	 "get the certificate's serial number"},
	{"get_subject", get_subject, METH_VARARGS,
	 "get the certificate's subject"},
	{"get_extension", get_extension, METH_VARARGS | METH_KEYWORDS,
	 "get the string representation of an extension by oid"},
	{"get_all_extensions", get_all_extensions, METH_VARARGS,
	 "get a dict of oid: value"},
	{NULL}
};

static PyTypeObject certificate_x509_type = {
	PyObject_HEAD_INIT(NULL)
	0,
	"_certificate.X509",
	sizeof(certificate_x509),
	0,                         /*tp_itemsize*/
	(destructor) certificate_x509_dealloc,
	0,                         /*tp_print*/
	0,                         /*tp_getattr*/
	0,                         /*tp_setattr*/
	0,                         /*tp_compare*/
	0,                         /*tp_repr*/
	0,                         /*tp_as_number*/
	0,                         /*tp_as_sequence*/
	0,                         /*tp_as_mapping*/
	0,                         /*tp_hash */
	0,                         /*tp_call*/
	0,                         /*tp_str*/
	0,                         /*tp_getattro*/
	0,                         /*tp_setattro*/
	0,                         /*tp_as_buffer*/
	Py_TPFLAGS_DEFAULT,        /*tp_flags*/
	"X509 Certificate",        /* tp_doc */
	0,		           /* tp_traverse */
	0,		           /* tp_clear */
	0,		           /* tp_richcompare */
	0,		           /* tp_weaklistoffset */
	0,		           /* tp_iter */
	0,		           /* tp_iternext */
	x509_methods,              /* tp_methods */
	0,             		   /* tp_members */
	0,                         /* tp_getset */
	0,                         /* tp_base */
	0,                         /* tp_dict */
	0,                         /* tp_descr_get */
	0,                         /* tp_descr_set */
	0,                         /* tp_dictoffset */
	0,			   /* tp_init */
	0,                         /* tp_alloc */
	0,			   /* tp_new */
};



static size_t
get_extension_by_object(X509 *x509, ASN1_OBJECT *obj, char **output) {
	int pos = X509_get_ext_by_OBJ(x509, obj, -1);
	if (pos < 0) {
		return 0;
	}
	X509_EXTENSION *ext = X509_get_ext(x509, pos);

	int tag;
	long len;
	long tc;
	char *p = ext->value->data;
	int res = ASN1_get_object (&p, &len, &tag, &tc, ext->value->length);

	switch(tag) {
	case V_ASN1_UTF8STRING:
		{
		ASN1_UTF8STRING *str = ASN1_item_unpack(ext->value,
			ASN1_ITEM_rptr(ASN1_UTF8STRING));
		*output = strdup(ASN1_STRING_data(str));
		return strlen(output);
		}
	case V_ASN1_OCTET_STRING:
		{
		ASN1_OCTET_STRING *octstr = ASN1_item_unpack(ext->value,
			ASN1_ITEM_rptr(ASN1_OCTET_STRING));
		*output = malloc(octstr->length);
		memcpy(*output, octstr->data, octstr->length);
		return octstr->length;
		}
	default:
		{
		BIO *bio = BIO_new(BIO_s_mem());
		X509V3_EXT_print(bio, ext, 0, 0);

		size_t size = BIO_ctrl_pending(bio);
		char *buf = malloc(sizeof(char) * size);
		BIO_read(bio, buf, size);
		*output = buf;
		BIO_free(bio);
		return size;
		}
	}
}

ASN1_OBJECT *
get_object_by_oid(const char *oid) {
	return OBJ_txt2obj(oid, 1);
}
	
static ASN1_OBJECT *
get_object_by_name(const char *name) {
	int nid = OBJ_txt2nid(name);
	return OBJ_nid2obj(nid);
}

static PyObject *
load_cert(PyObject *self, PyObject *args, PyObject *keywords) {
	const char *file_name = NULL;
	const char *pem = NULL;

	static char *keywordlist[] = {"file", "pem", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, keywords, "|ss", keywordlist,
					 &file_name, &pem)) {
		return NULL;
	}

	BIO *bio;
	if (pem != NULL) {
		bio = BIO_new_mem_buf(pem, strlen(pem));
	} else {
		bio = BIO_new_file(file_name, "r");
	}

	X509 *x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	BIO_free(bio);

	if (x509 == NULL) {
		Py_INCREF(Py_None);
		return Py_None;
	}

	certificate_x509 *py_x509 = _PyObject_New(&certificate_x509_type);
	py_x509->x509 = x509;
	return py_x509;
//	return PyCObject_FromVoidPtr(x509, X509_free);
}

static PyObject *
get_extension(certificate_x509 *self, PyObject *args, PyObject *keywords) {
	const char *oid = NULL;
	const char *name = NULL;

	static char *keywordlist[] = {"oid", "name", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, keywords, "|ss", keywordlist,
					 &oid, &name)) {
		return NULL;
	}

	char *value = NULL;
	size_t length;
	ASN1_OBJECT *obj = NULL;
	if (name != NULL) {
		obj = get_object_by_name(name);
	} else {
		obj = get_object_by_oid(oid);
	}

	if (obj == NULL) {
		Py_INCREF(Py_None);
		return Py_None;
	}

	length = get_extension_by_object(self->x509, obj, &value);
	if (value != NULL) {
		return PyString_FromStringAndSize(value, length);
	} else {
		Py_INCREF(Py_None);
		return Py_None;
	}
}

static PyObject *
get_all_extensions(certificate_x509 *self, PyObject *args) {
	if (!PyArg_ParseTuple(args, "")) {
		return NULL;
	}

	int i;
	int ext_count = X509_get_ext_count(self->x509);

	char oid[MAX_BUF];
	PyObject *dict = PyDict_New();
	for (i = 0; i < ext_count; i++) {
		X509_EXTENSION *ext = X509_get_ext(self->x509, i);

		OBJ_obj2txt(oid, MAX_BUF, ext->object, 1);
		PyObject *key = PyString_FromString(oid);

		char *value;
		size_t length = get_extension_by_object(self->x509, ext->object,
							&value);
		PyObject *dict_value = PyString_FromString(value);

		PyDict_SetItem(dict, key, dict_value);
	}

	return dict;

}
static PyObject *
get_serial_number(certificate_x509 *self, PyObject *args) {
	if (!PyArg_ParseTuple(args, "")) {
		return NULL;
	}

	ASN1_INTEGER *serial_asn = X509_get_serialNumber(self->x509);
	long serial = ASN1_INTEGER_get (serial_asn);

	return PyInt_FromLong(serial);
}

static PyObject *
get_subject(certificate_x509 *self, PyObject *args) {
	if (!PyArg_ParseTuple(args, "")) {
		return NULL;
	}

	X509_NAME *name = X509_get_subject_name(self->x509);
	int entries = X509_NAME_entry_count(name);
	int i;

	PyObject *dict = PyDict_New();
	for (i = 0; i < entries; i++) {
		X509_NAME_ENTRY *entry = X509_NAME_get_entry(name, i);
		ASN1_OBJECT *obj = X509_NAME_ENTRY_get_object(entry);
		ASN1_STRING *data = X509_NAME_ENTRY_get_data(entry);

		PyObject *key =
			PyString_FromString(OBJ_nid2sn(OBJ_obj2nid(obj)));
		PyObject *value =
			PyString_FromString(ASN1_STRING_data(data));
		PyDict_SetItem(dict, key, value);
	}

	return dict;
}

static PyObject *
time_to_string(ASN1_UTCTIME *time) {
	BIO *bio = BIO_new(BIO_s_mem());
	ASN1_UTCTIME_print(bio, time);

	size_t size = BIO_ctrl_pending(bio);
	char *buf = malloc(sizeof(char) * size);
	BIO_read(bio, buf, size);
	BIO_free(bio);

	return PyString_FromStringAndSize(buf, size);
}

static PyObject *
get_not_before(certificate_x509 *self, PyObject *args) {
	ASN1_UTCTIME *time = X509_get_notBefore(self->x509);
	return time_to_string(time);

//	Py_INCREF(Py_None);
//	return Py_None;
}

static PyObject *
get_not_after(certificate_x509 *self, PyObject *args) {
	ASN1_UTCTIME *time = X509_get_notAfter(self->x509);
	return time_to_string(time);

//	Py_INCREF(Py_None);
//	return Py_None;
}


static PyMethodDef cert_methods[] = {
	{"load", load_cert, METH_VARARGS | METH_KEYWORDS,
	 "load a certificate from a file"},
	{"get_serial_number", get_serial_number, METH_VARARGS,
	 "get the certificate's serial number"},
	{"get_subject", get_subject, METH_VARARGS,
	 "get the certificate's subject"},
	{"get_extension", get_extension, METH_VARARGS | METH_KEYWORDS,
	 "get the string representation of an extension by oid"},
	{"get_all_extensions", get_all_extensions, METH_VARARGS,
	 "get a dict of oid: value"},

	{NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC
init_certificate(void) {
	PyObject *module;
	module = Py_InitModule("_certificate", cert_methods);

	certificate_x509_type.tp_new = PyType_GenericNew;
	if (PyType_Ready(&certificate_x509_type) < 0) {
		return;
	}

	Py_INCREF(&certificate_x509_type);
	PyModule_AddObject(module, "X509", (PyObject *) &certificate_x509_type);
}