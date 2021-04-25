// FirmaPKSC7.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <atlstr.h>
//PYD+
//#include <string.h>
//#include <stdlib.h>
//#include <atlbase.h>
//#include <comutil.h>


//PYD-
#include <wincrypt.h>
#include <iostream>

#include "FirmaPKCS7.h"
#include "FirmaDigital.h"
#include "CertStore.h"

///Main Function. Uses 3 arguments
/// NIE  InputFile OutputFile
int main(int argc, char* argv[])
{
	//---------Display Command Lines Arguments ----
	int count;
	std::cout << "\nCommand-line arguments: argc=" << argc <<"\n";
	for (count = 0; count < argc; count++)
		std::cout << "  argv[" << count << "]   "<< argv[count] << "\n";
	//---------------------------------------------
	if (argc != 4) {
		std::cout << "Syntax is\n" << argv[0] << " NIF  InputFileName OutputFileName \n";
		exit(EXIT_FAILURE);
	}
	
	std::cout << "Starting execution!\n";

	FirmaDigital F;
	CertStore S;
	PCCERT_CONTEXT pCertContextSelFirma;
	long ret;  // DWORD
	LPTSTR Datos_Envio;
	
	
	char* Nif = argv[1];
	/*
	char* Nif=(char *)malloc(1001*2);
	memset(Nif, '\0', 1000);
	strcpy(Nif, argv[1]);
	*/

	FILE* fp = fopen(argv[2], "rb");  //PYD: Change to Binary
	if (fp == NULL)
	{
		std::cout << "Error while opening the Input file: " << argv[2] << "\n";
		std::cout << "the error was: " << strerror(errno) << "\n";
		exit(EXIT_FAILURE);
	}

	// Determine file size
	fseek(fp, 0, SEEK_END);
	size_t filesize = ftell(fp);
	char* Edi = (char *)malloc(filesize * 2 + 1000);
	//PYD: char* Edi = new char[filesize*2+1000]; //Try malloc instead
	rewind(fp);
	fread(Edi, sizeof(char), filesize, fp);
	Edi[filesize] = '\0';
	
	//BSTR Edi2 = (BSTR) "UNB+UNOA:1+ESB08000796:ZZ+AEATADUE:ZZ+210423:0856+AEDBB210277P01'UNH+AEDBB210277P02+CUSDEC:1:921:UN:ECS003'BGM+830+AEDBB210277P01+9'CST++EX:104:141+A:105:141++11:112:141+0855:113:148'LOC+35+ES::141'LOC+36+US::141'LOC+42+ES::141:000812'LOC+43+0841::148+DL01NC::148'GIS+0:109:141'RFF+ABJ:AEDBB210277P01'TDT+11++1'TPL+:::CMA CGM DALILA:QU'TDT+12++3'NAD+EX+ESD39002316::148++FREUDENBERG ESPAÑA SA-TELAS SIN TEL+CARRETERA C-17, KM.15+PARETS DEL VALLES++08150+ES'NAD+CN+++FREUDENBERG PM INDUSTRIAL+C/O INT. TEXTIL SOLUTIONS INC CLEVE+SALEM++ .+US'NAD+2+ESB08000796::148+ssibcn@basjosa.com+BAS & JOSA S.L.:::::'TOD+++FOB:106'LOC+7+:::BARCELONA'LOC+133+1::141'MOA+39:2736,96:EUR'MOA+ZZZ::EUR'UNS+D'CST+1+5603929090:122:148+10.00:117:141++:117:148'FTX+AAA+++TELAS SIN TEJER'LOC+27+ES::141+08::148'MEA+AAE+G+KGM:312'MEA+AAE+AAF+KGM:258,000'PAC++1'PCI++FREUDENBERG::1+PX'MOA+123:2736,96'DOC+:::N380+ES390051413'DTM+137:210422:101'DOC+:::N705+ESBL'DTM+137:210423:101'DOC+:::1217+ESCR-2111111472'DTM+137:210422:101'DOC+:::Y022+ESAEOF140000476U'DTM+137:140725:101'DOC+:::Y024+ESAEOC11000181II'DTM+137:111205:101'UNS+S'CNT+5:1'CNT+11:1'UNT+44:AEDBB210277P01'UNZ+1+AEDBB210277P01'";
	//BSTR Nif2 = (BSTR)"X1234567V";

	
	pCertContextSelFirma = S.FindCertContext(Nif, (unsigned long*)&ret, MODO_FIRMA);
	if (pCertContextSelFirma == NULL) {
		std::cout << "Failed to Get Certificate, error: " << ret << " for Nif=" << Nif << "\n\n";
		exit(EXIT_FAILURE);
	}

	//Reserva de memoria para el envio
	int lenvio = strlen((char*)Edi);  //PYD: was lstrlen
	Datos_Envio = new char[lenvio * 2 + 5000]; //[500000]
	//TEST

	ret = F.Firma((char *) Edi, pCertContextSelFirma, Datos_Envio);

	//Grabar el Resultado en Fichero
	FILE* outputFile = fopen(argv[3], "w");
	if (outputFile == NULL)
	{
		std::cout <<"ERROR: could not open output file ",argv[3]," \n";
		std::cout << "the error was: "<< strerror(errno) <<"\n";
		exit(EXIT_FAILURE);
	}
	fprintf(outputFile, "%s\n", Datos_Envio);
	fclose(outputFile);
	std::cout << "Done. Success.\n";
	exit(EXIT_SUCCESS);
	}
