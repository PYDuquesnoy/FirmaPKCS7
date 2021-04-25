/// Test the FirmaPKCS7.exe file to create and send a message
Class pkcs7.Demo Extends %RegisteredObject
{

Parameter EXEPROGRAM = "c:\temp\deiworld\FirmaPKCS7.exe";

// The Input file with the EDI String

Parameter EDIFILE = "c:\temp\deiworld\EDI.TXT";

/// The Output File with the Signed EDI
Parameter SIGNEDFILE = "C:\temp\deiworld\EDISIGNED.TXT";

/// There has to be a Certificate with the NIE as Subject in the Windows Certificate Store
Parameter NIE = "X2628158V";

/// The SSL Configuration defined a certificate to establish TSL communication with the server
/// The SSL Config has to be defined in the Mgmt Portal / Administration 
Parameter SSLCONFIG = "SSLNIE";

/* Notes on Certificates:
Export From the Windows Store using certmgr, choosing pkcs12 export format with private key
Generate PEM Public and Private keys with openssl
openssl pkcs12 -in path.p12 -out newfile.crt.pem -clcerts -nokeys
openssl pkcs12 -in path.p12 -out newfile.key.pem -nocerts -nodes
Create SSLConfig with these PEM Files (SSLNIE in this example)
*/
ClassMethod Run() As %Status
{
	#DIM tSC as %Status=$$$OK
	#DIM errObj as %Exception.AbstractException
	try {
		set tEDIString="UNB+UNOA:1+ESB08000796:ZZ+AEATADUE:ZZ+210423:0856+AEDBB210277P01'UNH+AEDBB210277P02+CUSDEC:1:921:UN:ECS003'BGM+830+AEDBB210277P01+9'CST++EX:104:141+A:105:141++11:112:141+0855:113:148'LOC+35+ES::141'LOC+36+US::141'LOC+42+ES::141:000812'LOC+43+0841::148+DL01NC::148'GIS+0:109:141'RFF+ABJ:AEDBB210277P01'TDT+11++1'TPL+:::CMA CGM DALILA:QU'TDT+12++3'NAD+EX+ESD39002316::148++FREUDENBERG ESPAÑA SA-TELAS SIN TEL+CARRETERA C-17, KM.15+PARETS DEL VALLES++08150+ES'NAD+CN+++FREUDENBERG PM INDUSTRIAL+C/O INT. TEXTIL SOLUTIONS INC CLEVE+SALEM++ .+US'NAD+2+ESB08000796::148+ssibcn@basjosa.com+BAS & JOSA S.L.:::::'TOD+++FOB:106'LOC+7+:::BARCELONA'LOC+133+1::141'MOA+39:2736,96:EUR'MOA+ZZZ::EUR'UNS+D'CST+1+5603929090:122:148+10.00:117:141++:117:148'FTX+AAA+++TELAS SIN TEJER'LOC+27+ES::141+08::148'MEA+AAE+G+KGM:312'MEA+AAE+AAF+KGM:258,000'PAC++1'PCI++FREUDENBERG::1+PX'MOA+123:2736,96'DOC+:::N380+ES390051413'DTM+137:210422:101'DOC+:::N705+ESBL'DTM+137:210423:101'DOC+:::1217+ESCR-2111111472'DTM+137:210422:101'DOC+:::Y022+ESAEOF140000476U'DTM+137:140725:101'DOC+:::Y024+ESAEOC11000181II'DTM+137:111205:101'UNS+S'CNT+5:1'CNT+11:1'UNT+44:AEDBB210277P01'UNZ+1+AEDBB210277P01'"
		
		//1---Write EDI to ASCII File
		Write "Opening EDI File to Write",!
		set tEDIFile=##Class(%Stream.FileCharacter).%New()
		do tEDIFile.LinkToFile(..#EDIFILE)
		do tEDIFile.Write(tEDIString)  //Only the String, no trailing CR+LF or any additional trailing characters
		do tEDIFile.%Close()
		
		//2---Execute the Exe File to generate a signature
		Write "Executing $ZF()",!
		//set retVal=$ZF(-100,"/LOGCMD /STDERR+=C:\temp\deiworld\err.log /STDOUT+=C:\temp\deiworld\out.log /ASYNC",..#EXEPROGRAM,..#NIE, ..#EDIFILE,..#SIGNEDFILE)
		set retVal=$ZF(-1,..#EXEPROGRAM_" "_..#NIE_" "_..#EDIFILE_" "_..#SIGNEDFILE)
		Write "Firma Result:",retVal,!
		hang 5   // because async
 		
		//3---Read the resulting Signed EDI
		Write "Opening SignedFile to Read Content",!
		set tSignedFile=##Class(%Stream.FileCharacter).%New()
		do tSignedFile.LinkToFile(..#SIGNEDFILE)
		Write "Signed File Size:",tSignedFile.Size,!
		
		set tSignedString=tSignedFile.Read(1000000,.tSC)   //Suppose all files <1MB
		$$$ThrowOnError(tSC)
		
		//4---Send as Post to Server
		Write "Sending Data to aeat Server",!
		set tHttp=##class(%Net.HttpRequest).%New()
		set tHttp.Server="www1.agenciatributaria.gob.es"
		set tURL="/L/inwinvoc/es.aeat.dit.adu.adht.infra.EntradaEdiJava"
		set tHttp.SSLConfiguration=..#SSLCONFIG
		set tHttp.Https=1
		do tHttp.SetHeader("Content-Type","application/x-www-form-urlencoded")
		Do tHttp.EntityBody.Write(tSignedString)
		set tSC=tHttp.Send("POST",tURL,0,1)
		$$$ThrowOnError(tSC)
		
		//5---Read Server Response
		#DIM tR as %Net.HttpResponse
		set tR=tHttp.HttpResponse
		Write "HTTP Response Code: ",tR.StatusCode,!
		set tPage=tR.Data.Read(32000)
		set tEDI=$piece($piece(tPage,"<RESPUESTA>",2),"</RESPUESTA>",1)
		Write !,"EDI RECIBIDO:",!,tEDI,!
		Break 
		
			
	}catch (errObj) {
		Write "CATCH:",errObj.DisplayString(),!
		set tSC=errObj.AsStatus()
		break   //Oh, I love Debugging
	}
	quit tSC
}

}
