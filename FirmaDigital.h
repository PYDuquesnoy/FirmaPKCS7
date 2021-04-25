#pragma once
#include <atlstr.h>
#include "FirmaPKCS7.h"
#include "Base64Coder.h"

class FirmaDigital
{

	//	IWebBrowser2* pWBApp;

public:
	DWORD Firma(LPCTSTR ediToSend, PCCERT_CONTEXT certName, LPTSTR Datos_Envio); //Firma, encripta y manda el EDI a la página de tratamiento automático de la AEAT
	FirmaDigital();
	virtual ~FirmaDigital();

protected:
	//	HRESULT GetPostData(LPVARIANT pvPostData, LPCTSTR datos);
	CString ParseCryptMessage(LPCTSTR firma); //Trata el mensaje encriptado pasado tratando caracteres especiales.
	BOOL CheckFileVersion(LPSTR szFileName, char* Version);

};
