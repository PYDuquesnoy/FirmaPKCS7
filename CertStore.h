#pragma once
#define MODO_INDIFERENTE	0
#define MODO_FIRMA			1
#define MODO_AUTENTICACION	2

class CertStore
{
public:
	CertStore();
	virtual ~CertStore();
	PCCERT_CONTEXT FindCertContext(LPCTSTR certName, DWORD* ret);
	PCCERT_CONTEXT FindCertContext(LPCTSTR certName, DWORD* ret, int modo);
	PCCERT_CONTEXT FindCertContext2(LPCTSTR certName, DWORD* ret);

};
