// FirmaDigital.cpp: implementation of the FirmaDigital class.
//
//////////////////////////////////////////////////////////////////////

#include "FirmaDigital.h"
#include <iostream>
//PYD
#include "FirmaPKCS7.h"
#include <tchar.h>

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

FirmaDigital::FirmaDigital()
{

}

FirmaDigital::~FirmaDigital()
{

}


// Funcion publica de la clase FirmaDigital que engloba todo el procedimiento
// de encriptación de un mensaje EDI. Se pasa también el nombre del 
// certificado a usar.

DWORD sha1(BYTE* Mensa, DWORD Lmensaje, BYTE Hash_Sha1[20]);


DWORD FirmaDigital::Firma(LPCTSTR xediToSend, PCCERT_CONTEXT pCertContextSel, LPTSTR Datos_Envio)
{

	CString	strPOSTDATA = "";
	CString ediToSend = "";


	//  PYD+: According to Doc 2.0, VIA is free text with 8 Chars max.
	//  ediToSend.Format("VIA=ADEDINET&VER=%s&DAT=%s", versiondll, xediToSend);
	ediToSend.Format("VIA=IRIS&DAT=%s", xediToSend);

	// Mod 17/09/2001 Generacion de la huella de la declaracion usando
	//                la funcion CryptHashMessage
#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

	DWORD				Lmensaje;			// Longitud de mensaje
	Lmensaje = lstrlen(ediToSend);

	std::cout << "FirmaDigital:Firma!\n";

	FILETIME ft2;
	GetSystemTimeAsFileTime(&ft2);

	BYTE* outByteFILETIME;
	DWORD  cbSizeEncodedFILETIME;

	// Se hace una solicitud de encriptar el filetime pasando NULL para obtener solo el tamaño
	CryptEncodeObject(0x10001, PKCS_UTC_TIME, &ft2, NULL, &cbSizeEncodedFILETIME);
	outByteFILETIME = (BYTE*)malloc(cbSizeEncodedFILETIME); // reservo memoria para la cadena encriptada
	// Vuelvo a llamar de nuevo, pasando el buffer de salida
	CryptEncodeObject(0x10001, PKCS_UTC_TIME, &ft2, outByteFILETIME, &cbSizeEncodedFILETIME);
	std::cout << "FileTime Encriptado\n";

	//mismo procedimiento que antes
	byte* outByte2;

	CRYPT_SMIME_CAPABILITIES mime_capabilities;
	CRYPT_SMIME_CAPABILITY mime_capability;

	//mime_capability.pszObjId = CA2T(szOID_RSA_SMIMECapabilities);
	mime_capability.pszObjId = (TCHAR*)_T(szOID_RSA_SMIMECapabilities);
	mime_capability.Parameters.cbData = 3;

	byte* abyte1;
	abyte1 = (byte*)malloc(3);
	abyte1[0] = 2;
	abyte1[1] = 1;
	abyte1[2] = 40;


	mime_capability.Parameters.pbData = abyte1;
	mime_capabilities.cCapability = 1;
	mime_capabilities.rgCapability = &mime_capability;


	DWORD  cbSizeEncoded;

	CryptEncodeObject(0x10001, PKCS_SMIME_CAPABILITIES, &mime_capabilities, NULL, &cbSizeEncoded);
	outByte2 = (byte*)malloc(cbSizeEncoded); // reservo memoria para la cadena encriptada
	CryptEncodeObject(0x10001, PKCS_SMIME_CAPABILITIES, &mime_capabilities, outByte2, &cbSizeEncoded);

	std::cout << "Mime Capabilities Encriptado\n";

	CRYPT_SIGN_MESSAGE_PARA message_para;
	memset(&message_para, 0, sizeof(CRYPT_SIGN_MESSAGE_PARA));



	message_para.cbSize = sizeof(CRYPT_SIGN_MESSAGE_PARA);
	message_para.dwMsgEncodingType = PKCS_7_ASN_ENCODING | X509_ASN_ENCODING;
	message_para.pSigningCert = pCertContextSel; // CERT_CONTEXT elegido. Certificado elegido.
	

	//message_para.HashAlgorithm.pszObjId = CA2T(szOID_OIWSEC_sha1);
	message_para.HashAlgorithm.pszObjId = (TCHAR*)_T(szOID_OIWSEC_sha1); // szOID_OIWSEC_sha1;
	message_para.HashAlgorithm.Parameters.cbData = NULL;


	message_para.cMsgCert = 1;
	message_para.rgpMsgCert = &pCertContextSel;
	message_para.cAuthAttr = 2;
	message_para.dwInnerContentType = 0;
	message_para.cMsgCrl = 0;
	message_para.cUnauthAttr = 0;
	message_para.dwFlags = 0;
	message_para.pvHashAuxInfo = NULL;

	PCRYPT_ATTRIBUTE atribute = new CRYPT_ATTRIBUTE[2];


	//PYD: atribute[0].pszObjId = CA2T(szOID_RSA_signingTime);
	atribute[0].pszObjId = (TCHAR*)_T(szOID_RSA_signingTime);
	atribute[0].cValue = 1;
	


	CRYPT_ATTR_BLOB blob1;
	blob1.cbData = cbSizeEncodedFILETIME;
	blob1.pbData = outByteFILETIME;
	atribute[0].rgValue = &blob1;

	//atribute[1].pszObjId = CA2T(szOID_RSA_SMIMECapabilities);
	atribute[1].pszObjId = (TCHAR*)_T(szOID_RSA_SMIMECapabilities);
	atribute[1].cValue = 1;



	CRYPT_ATTR_BLOB blob2;
	blob2.cbData = cbSizeEncoded;
	blob2.pbData = outByte2;
	atribute[1].rgValue = &blob2;

	message_para.rgAuthAttr = atribute;


	CString EDI(ediToSend);

	// Mod 16/07/2002 Se firma toda la declaracion
	CString EDIFirma(ediToSend);

	BYTE* TotpbMessage = (BYTE*)EDI.GetBuffer(0);
	DWORD TotcbMessage = strlen((char*)TotpbMessage); //+1;
	// Fin mod
	



	BYTE* pbMessage = (BYTE*)EDIFirma.GetBuffer(0);

	DWORD cbMessage = strlen((char*)pbMessage); //+1;

	const BYTE* MessageArray[] = { pbMessage };
	DWORD MessageSizeArray[1];
	MessageSizeArray[0] = cbMessage;

	// Dos pasos, el primero para calcular el tamaño del mensaje encriptado
	DWORD size = 120000;

	///PYD: this calculation crashes...
	/*
	if (!CryptSignMessage(&message_para, TRUE, 1, MessageArray, MessageSizeArray, NULL, &size))
	{
		std::cout << "Step9\n";

		//PYD+
		LPVOID lpMsgBuf;
		DWORD dw = GetLastError();

		FormatMessage(
			FORMAT_MESSAGE_ALLOCATE_BUFFER |
			FORMAT_MESSAGE_FROM_SYSTEM |
			FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL,
			dw,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			(LPTSTR)&lpMsgBuf,
			0, NULL);
		std::cout << (LPSTR)lpMsgBuf;
		//PYD-

		free(outByteFILETIME);
		free(abyte1);
		free(outByte2);
		delete atribute;
		return 400041;
	}
	*/

	BYTE* pCrypt;
	pCrypt = (BYTE*)malloc(size);
	for (int i = 0; i < (int)size; i++)
		pCrypt[i] = 49;


	// Se pasa el array construido, donde recibiremos el mensaje encriptado
	if (!CryptSignMessage(&message_para, TRUE, 1, MessageArray, MessageSizeArray, pCrypt, &size))
	{
		//PYD+
		LPVOID lpMsgBuf;
		DWORD dw = GetLastError();

		FormatMessage(
			FORMAT_MESSAGE_ALLOCATE_BUFFER |
			FORMAT_MESSAGE_FROM_SYSTEM |
			FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL,
			dw,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			(LPTSTR)&lpMsgBuf,
			0, NULL);
		std::cout << (LPSTR)lpMsgBuf;
		//PYD-

		free(outByteFILETIME);
		free(abyte1);
		free(outByte2);
		delete atribute;
		free(pCrypt);
		return 400042;
	}
	std::cout << "Despues CryptSignMessage!\n";

	// Codifica los mensajes encriptados en Base64
	// Mod 16/07/2002
	// Se suprime la codificacion en b64

	Base64Coder encoder;



	encoder.Encode(pCrypt, size);
	CString Firma = encoder.EncodedMessage();

	std::cout << "Firma " << Firma << "\n";
	// Fin modificacion 16/07/2002

		// Proceso previo que hay que hacer para enviar de forma correcta los datos al postdata
		// debido a que pueden aparecer caracteres especiales como el '+' y '/' 
		// Tambien se eliminan los caracteres especiales /n y /r




	CString outediToSend = ParseCryptMessage((LPCTSTR)xediToSend);
	CString outFIRMA = ParseCryptMessage((LPCTSTR)Firma);

	
	///PYD: strPOSTDATA.Format("VIA=ADEDINET&VER=%s&DAT=%s&FIR=%s", versiondll, outediToSend, outFIRMA);
	strPOSTDATA.Format("VIA=IRIS&DAT=%s&FIR=%s", outediToSend, outFIRMA);

	// Mod 17/09/2001

	strcpy(Datos_Envio, strPOSTDATA);

	free(outByteFILETIME);
	free(abyte1);
	free(outByte2);
	delete atribute;
	free(pCrypt);

	return (0);

}

// Funcion que elimina los caracteres especiales '\n' y '\r' y hace un tratamiento de 
// los caracteres de la trama a enviar. Este tratamiento es necesario para enviar de forma
// correcta los parámetros a la página certificados usando el método POST.

CString FirmaDigital::ParseCryptMessage(LPCTSTR firma)
{

	CString strOut;
	CString strAux;
	CString FIRMA(firma);
	long contador;
	int j = 0;

	contador = FIRMA.GetLength();
	char* buff = new char[contador * 2];

	for (int i = 0; i < contador; i++)
	{
		if (FIRMA.GetAt(i) == '+')
		{
			buff[j] = '%';
			j++;
			buff[j] = '2';
			j++;
			buff[j] = 'B';
			j++;
			//			strOut += "%2B";
			continue;
		}

		if (FIRMA.GetAt(i) == '/')
		{
			buff[j] = '%';
			j++;
			buff[j] = '2';
			j++;
			buff[j] = 'F';
			j++;
			//			strOut += "%2F";
			continue;
		}

		if (FIRMA.GetAt(i) == '%')
		{
			buff[j] = '%';
			j++;
			buff[j] = '2';
			j++;
			buff[j] = '5';
			j++;
			//			strOut += "%25";
			continue;
		}

		if (FIRMA.GetAt(i) == '&')
		{
			buff[j] = '%';
			j++;
			buff[j] = '2';
			j++;
			buff[j] = '6';
			j++;
			//			strOut += "%26";
			continue;
		}

		if (FIRMA.GetAt(i) != 13 && FIRMA.GetAt(i) != 10) // 13 es '\n' y 10 es '\r'
			buff[j] = FIRMA.GetAt(i);
		j++;
		//			strOut += FIRMA.GetAt(i);

	}
	strOut = buff;
	LPTSTR ww = strOut.GetBufferSetLength(j);
	strOut = ww;
	delete(buff);
	return strOut;
}


