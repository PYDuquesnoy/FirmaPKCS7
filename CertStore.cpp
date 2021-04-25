// CertStore.cpp: implementation of the seleccion class.
//
//////////////////////////////////////////////////////////////////////
#include <atlstr.h>
#include <string.h>
#include "CertStore.h"
#include <iostream>


#define CERT_STORE_NAME L"MY"
#define MY_TYPE ( X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)


#define EMISOR_O_DGP			"DIRECCION GENERAL DE LA POLICIA"
#define EMISOR_O_FNMT			"FNMT"
#define EMISOR_O_G_VALENCIANA   "Generalitat Valenciana"





//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CertStore::CertStore()
{

}

CertStore::~CertStore()
{

}


///////////////////////////////////////////////////////////////////////////
/////////
//Funcion que busca la lista de certificados instalados en una máquina.
//Si se le pasa un nombre de certificado, devuelve el certificado ( si existe )
//si no existe se devuelve NULL.
//Si se le pasa NULL en el parametro devuelve el primer certificado que encuentre
//
//Devuelve NULL si no hay certificados instalados en la maquina o si falla alguna 
//llamada al API de windows.
/////////
//////////////////////////////////////////////////////////////////////////

PCCERT_CONTEXT CertStore::FindCertContext(LPCTSTR certName, DWORD* ret)
{
	return FindCertContext(certName, ret, 0);
}



PCCERT_CONTEXT CertStore::FindCertContext(LPCTSTR certName, DWORD* ret, int modo)
{
	USES_CONVERSION;
	HCRYPTPROV hProv = 0;
	DWORD Error;


	HCERTSTORE hCertStore;
	PCCERT_CONTEXT pSignerCert;


	// Abrir almacen de certificados
	if (!(hCertStore = CertOpenStore(
		CERT_STORE_PROV_SYSTEM,
		0,
		NULL,
		CERT_SYSTEM_STORE_CURRENT_USER,
		CERT_STORE_NAME)))
	{

		*ret = 300041;
		return NULL;
	}
	std::cout << "CertStore:FindCertContext\n";

	PCCERT_CONTEXT pCertNext = NULL;
	//   int contador = 0;
	PCCERT_CONTEXT punthelp = NULL;
	int longhelp = 32000;
	int longitud;

	while (pSignerCert = CertFindCertificateInStore(hCertStore,
		MY_TYPE,
		0,
		CERT_FIND_SUBJECT_STR,
		(LPVOID)A2W(certName),  //PYDW: A2W(certName)
		pCertNext))

	{

		pCertNext = pSignerCert;

		PCERT_INFO pCertInfo = pSignerCert->pCertInfo;

		// Se mira la validez del certificado
		FILETIME ft;

		GetSystemTimeAsFileTime(&ft);
		long j5 = CertVerifyTimeValidity(&ft, pCertInfo); // retorna cero si el certificado es valido
		Error = GetLastError();
		if (j5 != 0)
		{
			*ret = 300044;
			continue;
			//	return NULL; 
		}


		// Se coge información del certificado
		LPSTR pszName;
		DWORD cbName;
		DWORD dwStrType = CERT_X500_NAME_STR;//CERT_OID_NAME_STR;

		cbName = CertNameToStr(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
			&(pSignerCert->pCertInfo->Subject), dwStrType, NULL, 0);

		pszName = (char*)malloc(cbName);


		// En este ejemplo se busca un certificado por nombre en el sujeto
		CERT_NAME_BLOB pCertName = pCertInfo->Subject;

		CertNameToStr(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, &pCertName,
			dwStrType, pszName, cbName);

		CString strNameCertCompleto(pszName);

		//PYD+
		std::cout << "Subject:" << strNameCertCompleto << " \n";
		//PYD-

		// Busco que el la organización FNMT
		//if ( strNameCertCompleto.Find("O=FNMT") == -1 )
		//	continue; // El certificado actual no ha sido espedido por la FNMT



		// Busco el COMMON_NAME del certificado
		int j;
		if ((j = strNameCertCompleto.Find("CN=")) == -1)
		{
			*ret = 300045;
			free(pszName);
			continue;
			//		return NULL;
		}


		// ********** USO DE LA CLAVE.  -------
		// El código se carga en la variable BYTE pbKeyUsage.
		//.#define CERT_DIGITAL_SIGNATURE_KEY_USAGE     0x80  
		//.#define CERT_NON_REPUDIATION_KEY_USAGE       0x40  
		//.#define CERT_KEY_ENCIPHERMENT_KEY_USAGE      0x20
		//.#define CERT_DATA_ENCIPHERMENT_KEY_USAGE     0x10
		//.#define CERT_KEY_AGREEMENT_KEY_USAGE         0x08
		//.#define CERT_KEY_CERT_SIGN_KEY_USAGE         0x04
		//.#define CERT_OFFLINE_CRL_SIGN_KEY_USAGE      0x02
		//.#define CERT_CRL_SIGN_KEY_USAGE              0x02
		//.#define CERT_ENCIPHER_ONLY_KEY_USAGE         0x01
		// Byte[1]
		//.#define CERT_DECIPHER_ONLY_KEY_USAGE         0x80
		// DNIe: Uso de la Clave: Firma digital(80)--> AUTENTICACION
		// DNIe: Uso de la Clave: Sin Repudio(40)  --> FIRMA
		// FNMT: Uso de la Clave: Firma digital, Cifrado de clave(a0) --> AUTENTICACION y FIRMA    a0=80+20
		// CAGVA: Uso de la Clave: Firma digital(80) --> AUTENTICACION y FIRMA
		CString uso;
		BYTE pbKeyUsage = 0;
		CertGetIntendedKeyUsage(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, pCertInfo, &pbKeyUsage, 1);


		// ********* Información del EMISOR **********
		//  Support the following X500 Keys:
//
//  Key         Object Identifier               RDN Value Type(s)
//  ---         -----------------               -----------------
//  CN          szOID_COMMON_NAME               Printable, Unicode
//  L           szOID_LOCALITY_NAME             Printable, Unicode
//  O           szOID_ORGANIZATION_NAME         Printable, Unicode
//  OU          szOID_ORGANIZATIONAL_UNIT_NAME  Printable, Unicode
//  E           szOID_RSA_emailAddr             Only IA5
//  Email       szOID_RSA_emailAddr             Only IA5
//  C           szOID_COUNTRY_NAME              Only Printable
//  S           szOID_STATE_OR_PROVINCE_NAME    Printable, Unicode
//  ST          szOID_STATE_OR_PROVINCE_NAME    Printable, Unicode
//  STREET      szOID_STREET_ADDRESS            Printable, Unicode
//  T           szOID_TITLE                     Printable, Unicode
//  Title       szOID_TITLE                     Printable, Unicode
//  G           szOID_GIVEN_NAME                Printable, Unicode
//  GivenName   szOID_GIVEN_NAME                Printable, Unicode
//  I           szOID_INITIALS                  Printable, Unicode
//  Initials    szOID_INITIALS                  Printable, Unicode
//  SN          szOID_SUR_NAME                  Printable, Unicode
//  DC          szOID_DOMAIN_COMPONENT          IA5, UTF8

		char valorOid[256];
		CString strEmisor_CN;
		///PYD+. cast to (void *)
		// Obtiene el Common Name (CN) del emisor del certificado
		if (CertGetNameString(pSignerCert, CERT_NAME_ATTR_TYPE, CERT_NAME_ISSUER_FLAG,
			(void*)szOID_COMMON_NAME, valorOid, 255) > 1)
			strEmisor_CN = (CString)valorOid;

		// Obtiene el Organization (O) del emisor del certificado
		CString strEmisor_O;
		if (CertGetNameString(pSignerCert, CERT_NAME_ATTR_TYPE, CERT_NAME_ISSUER_FLAG,
			(void*)szOID_ORGANIZATION_NAME, valorOid, 255) > 1)
			strEmisor_O = (CString)valorOid;

		// Obtiene el Organizational Unit (OU) del emisor del certificado
		CString strEmisor_OU;
		if (CertGetNameString(pSignerCert, CERT_NAME_ATTR_TYPE, CERT_NAME_ISSUER_FLAG,
			(void*)szOID_ORGANIZATIONAL_UNIT_NAME, valorOid, 255) > 1)
			strEmisor_OU = (CString)valorOid;
		// *********


		// CRITERIO DE SELECCIÓN DE CERTIFICADOS...
		// Se eliminan los certificados que no valen...
		// - En modo AUTENTICACION, solo puedo utilizar certificados cuyo 'Uso de Clave' tenga el bit 7 activado 
		//   (es decir, valor 0x80 o superior).
		// - En modo FIRMA, podemos utilizar todos los certificados. EXCEPTO para el DNIe que  
		//   solo puedo utilizar certificados cuyo 'Uso de Clave' NO tenga el bit 7 (es decir, valor 0x80 o superior).
		if ((modo == MODO_AUTENTICACION && !(pbKeyUsage & 0x80)))  continue;

		if (modo == MODO_FIRMA) {
			if ((strEmisor_O.Compare(EMISOR_O_DGP) == 0) && (pbKeyUsage & 0x80)) {
				continue;
			}
		}


		// ******** de los certificados SELECCIONADOS se toma el más corto....
		longitud = strNameCertCompleto.GetLength();
		if (longitud < longhelp) {
			longhelp = longitud;

			if (punthelp)
				CertFreeCertificateContext(punthelp);

			punthelp = CertDuplicateCertificateContext(pSignerCert);
		}

		//CString NameCert;
		//NameCert = strNameCertCompleto.Mid(j+4); 

		free(pszName);


	}


	*ret = (punthelp) ? 0 : 300048;
	return punthelp;


}





PCCERT_CONTEXT CertStore::FindCertContext2(LPCTSTR certName, DWORD* ret)
{
	USES_CONVERSION;
	HCRYPTPROV hProv = 0;
	DWORD Error;


	HCERTSTORE hCertStore;
	PCCERT_CONTEXT pSignerCert;


	// Abrir almacen de certificados
	if (!(hCertStore = CertOpenStore(
		CERT_STORE_PROV_SYSTEM,
		0,
		NULL,
		CERT_SYSTEM_STORE_CURRENT_USER,
		CERT_STORE_NAME)))
	{

		*ret = 300041;
		return NULL;
	}

	PCCERT_CONTEXT pCertNext = NULL;
	//   int contador = 0;
	PCCERT_CONTEXT punthelp = NULL;
	int longhelp = 32000;
	//int longitud;

	while (pSignerCert = CertFindCertificateInStore(hCertStore,
		MY_TYPE,
		0,
		CERT_FIND_SUBJECT_STR,
		(LPVOID)A2W(certName),
		pCertNext))

	{

		pCertNext = pSignerCert;

		PCERT_INFO pCertInfo = pSignerCert->pCertInfo;

		// Se mira la validez del certificado
		FILETIME ft;

		GetSystemTimeAsFileTime(&ft);
		long j5 = CertVerifyTimeValidity(&ft, pCertInfo); // retorna cero si el certificado es valido
		Error = GetLastError();
		if (j5 != 0)
		{
			*ret = 300044;
			continue;
			//	return NULL; 
		}


		// Se coge información del certificado
		LPSTR pszName;
		DWORD cbName;
		DWORD dwStrType = CERT_X500_NAME_STR;//CERT_OID_NAME_STR;

		cbName = CertNameToStr(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
			&(pSignerCert->pCertInfo->Subject), dwStrType, NULL, 0);

		pszName = (char*)malloc(cbName);

		// En este ejemplo se busca un certificado por nombre en el sujeto
		CERT_NAME_BLOB pCertName = pCertInfo->Subject;

		CertNameToStr(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, &pCertName,
			dwStrType, pszName, cbName);

		CString strNameCertCompleto(pszName);


		// Busco el 
		char buscar[90];
		strcpy(buscar, "OID.2.5.4.5=");
		strcat(buscar, certName);
		for (int x = 0; x < strlen(buscar); x++) {
			buscar[x] = toupper(buscar[x]);
		}

		int j;

		if ((j = strNameCertCompleto.Find(buscar)) == -1)
		{
			*ret = 300045;
			free(pszName);
			continue;
		}
		else {
			if (punthelp) CertFreeCertificateContext(punthelp);
			punthelp = CertDuplicateCertificateContext(pSignerCert);
			break;
		}

	}

	*ret = (punthelp) ? 0 : 300048;
	return punthelp;

	PCCERT_CONTEXT pCertContext = NULL;

}