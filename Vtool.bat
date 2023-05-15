:: --------------------------------------------------------------------------------------------     Version Control     --------------------------------------------------------------------------------------------
:: X.0.0 = Big Changes
:: 0.X.0 = New features
:: 0.0.X = Small Fixes
SET ScriptVersion=Version 1.0.0



@ECHO OFF
setlocal enabledelayedexpansion



:: API Check
IF not exist "%CD%\Data\ApiKey\" (
    mkdir "%CD%\Data\ApiKey"
)
IF not exist "%CD%\Data\ApiKey\Apikey.txt" (
    GOTO VERIFYVTAPI
)



:: Initial Settings
:INITIALSETTINGS
IF not exist "%CD%\Data\Settings\" (
    mkdir "%CD%\Data\Settings"
)
IF not exist "%CD%\Data\Settings\Settings.txt" (
    GOTO SETTINGS
)



:: Initial Setup
:STARTSCRIPT
SET /P ApiKey=<"Data\ApiKey\Apikey.txt"
for /f "tokens=1,2 delims==" %%a in (Data\Settings\Settings.txt) do (
    SET SettingsOption=%%a
    SET SettingsValue=%%b
    IF "!SettingsOption!"=="RegionOption" SET RegionOption=!SettingsValue!
)
IF %RegionOption%==1 (
    SET Month=%date:~4,2%
    SET Day=%date:~7,2%
    SET Year=%date:~10,4%
    SET Hour=%time:~0,2%
    SET Minute=%time:~3,2%
    SET Second=%time:~6,2%
)
IF %RegionOption%==2 (
   SET Month=%date:~3,2%
    SET Day=%date:~0,2%
    SET Year=%date:~6,4%
    SET Hour=%time:~0,2%
    SET Minute=%time:~3,2%
    SET Second=%time:~6,2% 
)
IF not exist "%CD%\Data\Temp" mkdir "%CD%\Data\Temp"
IF not exist "%CD%\Results" mkdir "%CD%\Results"
IF not exist "%CD%\Data\Logs" mkdir "%CD%\Data\Logs"



:: Vtool Menu
:MENU
CLS
ECHO          [96mVtool - %ScriptVersion%[0m
ECHO.
ECHO 1 - IP Analysis
ECHO 2 - IP Analysis (File Input)
ECHO 3 - IP Analysis + Rescan (File Input)
ECHO 4 - Domain Analysis
ECHO 5 - Domain Analysis (File Input)
ECHO 6 - Domain Analysis + Rescan (File Input)
ECHO 7 - Hash Analysis
ECHO 8 - Hash Analysis (File Input)
ECHO.
ECHO A - API Key Change
ECHO.
ECHO D - API Daily Quota  
ECHO.
ECHO S - Settings
ECHO.
ECHO H - Help
ECHO.
ECHO 0 - Sair
ECHO.
ECHO.
SET /P MenuOption=Choose One Option: 



:: Menu Options  
IF %MenuOption%==1 GOTO IPSEARCH
IF %MenuOption%==2 GOTO FILEIPSEARCH
IF %MenuOption%==3 GOTO RESCANPLUSANALYSISIP
IF %MenuOption%==4 GOTO DOMAINSEARCH
IF %MenuOption%==5 GOTO FILEDOMAINSEARCH
IF %MenuOption%==6 GOTO RESCANPLUSANALYSISDOMAIN
IF %MenuOption%==7 GOTO HASHSEARCH
IF %MenuOption%==8 GOTO FILEHASHSEARCH
IF %MenuOption%==0 GOTO EOF
IF /i %MenuOption%==A GOTO VERIFYVTAPI
IF /i %MenuOption%==D GOTO APIDAILYQUOTA
IF /i %MenuOption%==S GOTO SETTINGS
IF /i %MenuOption%==H GOTO HELP
IF /i %MenuOption%==help GOTO HELP



:: Exception
ECHO.
ECHO.
ECHO This option is not available, Press Any Key to Return
ECHO.
PAUSE >nul
GOTO MENU 



:: 1 - IP Search
:IPSEARCH
SET "Ips=" 
CLS
ECHO          1 - IP Search
ECHO.
SET /p Ips="Paste One or More IPs: " 
IF "%Ips%"=="0" GOTO MENU
IF "%Ips%"=="" GOTO IPSEARCH
ECHO.
Data\vt.exe ip -k %ApiKey% --include=_id,as_owner,asn,network,country,last_analysis_stats.harmless,last_analysis_stats.malicious,reputation,tags %Ips%
ECHO.
ECHO ------------------------------------------------------------------------------------
SET /P IpOption="Press ENTER to Continue or "0" to Menu: "
IF "%IpOption%"=="0" GOTO MENU 
GOTO IPSEARCH



:: 2 - IP - Analysis (File Input)
:FILEIPSEARCH
CLS
ECHO          2 - IP - Analysis (File Input)
ECHO.
SET /p InputTextFile=Enter the input file name: 
IF "%InputTextFile%"=="0" GOTO MENU 
SET "OutputIpFilename2=IP Analysis Results %Year%-%Month%-%Day% %Hour%_%Minute%_%Second%.csv"
ECHO IP,AS Owner,ASN,Continent,Country,Malicious,Last Modification Date,Network,Regional Internet Registry,Reputation,Votes Harmless,Votes Malicious > "%CD%\Results\%OutputIpFilename2%"
SET Return=RETURNFILEIPSEARCH
GOTO COUNT1
:RETURNFILEIPSEARCH
for /F "tokens=* delims=" %%d in (%InputTextFile%) do (
    CLS
    SET Format=
    SET /a Counter1+=1
    ECHO VT API Tool - Scan IP Request
    Echo.
    Echo.
    ECHO Progress: !Counter1! / %LinesCount%
    ECHO.
    ECHO IP: %%d
    ECHO.
    ECHO.
    Data\vt.exe ip -k %ApiKey% --include=_id,as_owner,asn,continent,country,last_analysis_stats.malicious,last_modification_date,network,regional_internet_registry,reputation,total_votes --format csv "%%d" > "%CD%\Data\Temp\Temp.txt"
    for /f "tokens=*" %%v in ("%CD%\Data\Temp\Temp.txt") do (
        SET Format=!Format! %%v    
    )
    more +1 "%CD%\Data\Temp\Temp.txt" >> "%CD%\Results\%OutputIPFilename2%"
    TIMEOUT 15
    ECHO.
    ECHO All IPs were Scaned / Analyzed.
    ECHO.
)
ECHO.
ECHO.
ECHO Process has ended!
ECHO.
ECHO ------------------------------------------------------------------------------------
SET /P FileIpSearchOption="Press ENTER to Continue or "0" to Menu: "
IF "%FileIpSearchOption%"=="0" GOTO MENU 
GOTO FILEIPSEARCH



:: 3 - IP - Rescan + Analysis (File Input)
:RESCANPLUSANALYSISIP
CLS
ECHO          3 - IP - Rescan + Analysis (File Input)
ECHO.
SET /p InputTextFile=Enter the input file name:  
IF "%InputTextFile%"=="0" GOTO MENU 
ECHO.
SET "OutputIpFilename1=IP Scan Request %Year%-%Month%-%Day% %Hour%_%Minute%_%Second%.txt"
SET "OutputIpFilename2=IP Analysis Results %Year%-%Month%-%Day% %Hour%_%Minute%_%Second%.csv"
ECHO IP,AS Owner,ASN,Continent,Country,Malicious,Last Modification Date,Network,Regional Internet Registry,Reputation,Votes Harmless,Votes Malicious > "%CD%\Results\%OutputIpFilename2%"
SET Return=RETURNRESCANPLUSANALYSISIP
GOTO COUNT1
:RETURNRESCANPLUSANALYSISIP
for /F "tokens=* delims=" %%d in (%InputTextFile%) do (
    CLS
    SET /a Counter1+=1
    SET Format=
    ECHO VT API Tool - Scan IP Request
    ECHO.
    ECHO Please Wait until Complete Each Phase
    Echo.
    Echo.
    ECHO Progress: !Counter1! / %LinesCount%
    ECHO.
    ECHO IP: %%d
    ECHO.
    ECHO Scaning...
    Data\vt.exe scan url -k %ApiKey% "%%d" >> "%CD%\Data\Logs\%OutputIpFilename1%"
    TIMEOUT 20
    ECHO.
    ECHO.
    ECHO.
    ECHO Requesting Results...
    Data\vt.exe url -k %ApiKey% --include=_id,as_owner,asn,continent,country,last_analysis_stats.malicious,last_modification_date,network,regional_internet_registry,reputation,total_votes --format csv "%%d" > "%CD%\Data\Temp\Temp.txt"
    for /f "tokens=*" %%v in ("%CD%\Data\Temp\Temp.txt") do (
        SET Format=!Format! %%v    
    )
    more +1 "%CD%\Data\Temp\Temp.txt" >> "%CD%\Results\%OutputIpFilename2%"
    TIMEOUT 10
    ECHO.
    ECHO All IPs were Scaned / Analyzed.
    ECHO.
)
ECHO.
ECHO.
ECHO Scan has Ended!
ECHO.
ECHO ------------------------------------------------------------------------------------
SET /P IpOption="Press ENTER to Continue or "0" to Menu: "
IF "%IpOption%"=="0" GOTO MENU 
GOTO RESCANPLUSANALYSISIP



:: 4 - Domain Search
:DOMAINSEARCH
CLS
ECHO          4 - Domain Search
ECHO.
SET "Domains=" 
SET /p Domains="Insert one or more Domains: "
IF "%Domains%"=="0" GOTO MENU
IF "%Domains%"=="" GOTO DOMAINSEARCH
ECHO.
Data\vt.exe url -k %ApiKey% --include=url,last_analysis_stats.malicious %Domains%
ECHO.
ECHO ------------------------------------------------------------------------------------
SET /P HasheOption="Press ENTER to Continue or "0" to Menu: "
IF "%HasheOption%"=="0" GOTO MENU 
GOTO DOMAINSEARCH



:: 5 - Domain - Analysis (File Input)
:FILEDOMAINSEARCH
CLS
ECHO          5 - Domain - Analysis (File Input)
ECHO.
SET /p InputTextFile=Enter the input file name: 
IF "%InputTextFile%"=="0" GOTO MENU 
SET "OutputDomainFilename2=Domain Analysis Results %Year%-%Month%-%Day% %Hour%_%Minute%_%Second%.csv"
ECHO First Submission Date,Last Analysis Date,Harmless,Malicious,Suspicious,Undetected,Last Final Url,Last Modification Date,Last Submission Date,Reputation,Times Submitted,Tld,Votes Harmless,Votes Malicious,Url > "%CD%\Results\%OutputDomainFilename2%"
SET Return=RETURNFILEDOMAINSEARCH
GOTO COUNT1
:RETURNFILEDOMAINSEARCH
for /F "tokens=* delims=" %%d in (%InputTextFile%) do (
    CLS
    SET Format=
    SET /a Counter1+=1
    ECHO VT API Tool - Scan Domain Request
    Echo.
    Echo.
    ECHO Progress: !Counter1! / %LinesCount%
    ECHO.
    ECHO Domain: %%d
    ECHO.
    ECHO.
    Data\vt.exe url -k %ApiKey% --include=first_submission_date,last_analysis_date,last_analysis_stats,last_final_url,last_modification_date,last_submission_date,reputation,times_submitted,tld,total_votes,url --exclude=last_analysis_stats.timeout --format csv "%%d" > "%CD%\Data\Temp\Temp.txt"
    for /f "tokens=*" %%v in ("%CD%\Data\Temp\Temp.txt") do (
        SET Format=!Format! %%v    
    )
    more +1 "%CD%\Data\Temp\Temp.txt" >> "%CD%\Results\%OutputDomainFilename2%"
    TIMEOUT 15
    ECHO.
    ECHO All Domains were Scaned / Analyzed.
    ECHO.
)
ECHO.
ECHO.
ECHO Process has ended!
ECHO.
ECHO ------------------------------------------------------------------------------------
SET /P FileDomainSearchOption="Press ENTER to Continue or "0" to Menu: "
IF "%FileDomainSearchOption%"=="0" GOTO MENU 
GOTO FILEDOMAINSEARCH



:: 6 - Domain - Rescan + Analysis (File Input)
:RESCANPLUSANALYSISDOMAIN
CLS
ECHO          6 - Domain - Rescan + Analysis (File Input)
ECHO.
SET /p InputTextFile=Enter the input file name: 
IF "%InputTextFile%"=="0" GOTO MENU 
ECHO.
SET "OutputDomainFilename1=Domain Scan Request %Year%-%Month%-%Day% %Hour%_%Minute%_%Second%.txt"
SET "OutputDomainFilename2=Domain Analysis Results %Year%-%Month%-%Day% %Hour%_%Minute%_%Second%.csv"
ECHO First Submission Date,Last Analysis Date,Harmless,Malicious,Suspicious,Undetected,Last Final Url,Last Modification Date,Last Submission Date,Reputation,Times Submitted,Tld,Votes Harmless,Votes Malicious,Url > "%CD%\Results\%OutputDomainFilename2%"
SET Return=RETURNRESCANPLUSANALYSISDOMAIN
GOTO COUNT1
:RETURNRESCANPLUSANALYSISDOMAIN
for /F "tokens=* delims=" %%d in (%InputTextFile%) do (
    CLS
    SET /a Counter1+=1
    SET Format=
    ECHO VT API Tool - Scan Domain Request
    ECHO.
    ECHO Please Wait until Complete Each Phase
    Echo.
    Echo.
    ECHO Progress: !Counter1! / %LinesCount%
    ECHO.
    ECHO Domain: %%d
    ECHO.
    ECHO Scaning...
    Data\vt.exe scan url -k %ApiKey% "%%d" >> "%CD%\Data\Logs\%OutputDomainFilename1%"
    TIMEOUT 20
    ECHO.
    ECHO.
    ECHO.
    ECHO Requesting Results...
    Data\vt.exe url -k %ApiKey% --include=first_submission_date,last_analysis_date,last_analysis_stats,last_final_url,last_modification_date,last_submission_date,reputation,times_submitted,tld,total_votes,url --exclude=last_analysis_stats.timeout --format csv "%%d" > "%CD%\Data\Temp\Temp.txt"
    for /f "tokens=*" %%v in ("%CD%\Data\Temp\Temp.txt") do (
        SET Format=!Format! %%v    
    )
    more +1 "%CD%\Data\Temp\Temp.txt" >> "%CD%\Results\%OutputDomainFilename2%"
    TIMEOUT 10
    ECHO.
    ECHO All Domains were Scaned / Analyzed.
    ECHO.
)
ECHO.
ECHO.
ECHO Scan has Ended!
ECHO.
ECHO ------------------------------------------------------------------------------------
SET /P DomainOption="Press ENTER to Continue or "0" to Menu: "
IF "%DomainOption%"=="0" GOTO MENU 
GOTO RESCANPLUSANALYSISDOMAIN



:: 7 - Hash Search
:HASHSEARCH
CLS
ECHO          7 - Hash Search
ECHO.
SET "Hashes=" 
SET /p Hashes="Insert one or more Hashes: "
IF "%Hashes%"=="0" GOTO MENU
IF "%Hashes%"=="" GOTO HASHSEARCH
ECHO.
Data\vt.exe file -k %ApiKey% --include=_id,crowdsourced_yara_results,last_analysis_stats.malicious,last_analysis_stats.harmless,md5,sha1,sha256 %Hashes%
ECHO.
ECHO ------------------------------------------------------------------------------------
SET /P HasheOption="Press ENTER to Continue or "0" to Menu: "
IF "%HasheOption%"=="0" GOTO MENU 
GOTO HASHSEARCH



:: 8 - Hash - Analysis (File Input)
:FILEHASHSEARCH
CLS
ECHO          8 - Hash - Analysis (File Input)
ECHO.
SET /p InputTextFile=Enter the input file name: 
IF "%InputTextFile%"=="0" GOTO MENU 
SET "OutputHashFilename2=Hash Analysis Results %Year%-%Month%-%Day% %Hour%_%Minute%_%Second%.csv"
ECHO Hash,Creation Date,Malicious,Last Modification Date,Last Submission Date,Magic,Meaningful Name,Names,Suggested Threat Label,Reputation,Size,Times Submitted,Votes Harmless,Votes Malicious,Type Description,Type Extension > "%CD%\Results\%OutputHashFilename2%"
SET Return=RETURNFILEHASHSEARCH
GOTO COUNT1
:RETURNFILEHASHSEARCH
for /F "tokens=* delims=" %%d in (%InputTextFile%) do (
    CLS
    SET Format=
    SET /a Counter1+=1
    ECHO VT API Tool - Scan Hash Request
    Echo.
    Echo.
    ECHO Progress: !Counter1! / %LinesCount%
    ECHO.
    ECHO Hash: %%d
    ECHO.
    ECHO.
    Data\vt.exe file -k %ApiKey% --include=_id,creation_date,last_analysis_stats.malicious,last_modification_date,last_submission_date,magic,meaningful_name,names,popular_threat_classification.suggested_threat_label,reputation,size,times_submitted,total_votes.harmless,total_votes.malicious,type_description,type_extension --format csv "%%d" > "%CD%\Data\Temp\Temp.txt"
    for /f "tokens=*" %%v in ("%CD%\Data\Temp\Temp.txt") do (
        SET Format=!Format! %%v    
    )
    more +1 "%CD%\Data\Temp\Temp.txt" >> "%CD%\Results\%OutputHashFilename2%"
    TIMEOUT 15
    ECHO.
    ECHO All Hashes were Scaned / Analyzed.
    ECHO.
)
ECHO.
ECHO.
ECHO Process has ended!
ECHO.
ECHO ------------------------------------------------------------------------------------
SET /P FileHashSearchOption="Press ENTER to Continue or "0" to Menu: "
IF "%FileHashSearchOption%"=="0" GOTO MENU 
GOTO FILEHASHSEARCH



:: Progress Count
:COUNT1
SET /a Counter1=0
SET LinesCount=0
FOR /f "tokens=*" %%a in (%InputTextFile%) do (
    SET /a LinesCount+=1
)
GOTO %Return%



:: Script Settings
:SETTINGS
CLS
SET Mo1=%date:~4,2%
SET Da1=%date:~7,2%
SET Ye1=%date:~10,4%
SET Ho1=%time:~0,2%
SET Mi1=%time:~3,2%
SET Se1=%time:~6,2%
SET Mo2=%date:~3,2%
SET Da2=%date:~0,2%
SET Ye2=%date:~6,4%
SET Ho2=%time:~0,2%
SET Mi2=%time:~3,2%
SET Se2=%time:~6,2% 
SET RegionOption=
ECHO          S - Settings 
ECHO.
ECHO Today Date and Time:   %date%   %time%
ECHO.
ECHO.
ECHO Chose your current Date/Time settings:
ECHO.
ECHO 1 - English:
ECHO Month: %Mo1%
ECHO Day= %Da1%
ECHO Year= %Ye1%
ECHO Hour= %Ho1%
ECHO Minute= %Mi1%
ECHO Second= %Se1%
ECHO.
ECHO.
ECHO 2 - Portuguese
ECHO Day= %Da2%
ECHO Year= %Ye2%
ECHO Hour= %Ho2%
ECHO Minute= %Mi2%
ECHO Second= %Se2%
ECHO.
ECHO.
SET /P RegionOption=What are your Region Seetings 1 or 2? 
ECHO. 
ECHO.
IF "!RegionOption!"=="" (
    GOTO SETTINGS
)
IF %RegionOption%==1 ( 
    ECHO RegionOption=%RegionOption% > "%CD%\Data\Settings\Settings.txt"
    ECHO Region Option changed to: %RegionOption% - English
    ECHO.
    ECHO.
    PAUSE
    GOTO STARTSCRIPT
)
IF %RegionOption%==2 (
    ECHO RegionOption=%RegionOption% > "%CD%\Data\Settings\Settings.txt"
    ECHO Region Option changed to: %RegionOption% - Portuguese
    ECHO.
    ECHO.
    PAUSE
    GOTO STARTSCRIPT
)
ECHO.
ECHO.
ECHO This option is not available, Press Any Key to Return
PAUSE >nul
GOTO SETTINGS 



:: H - Help
:HELP
CLS
ECHO          H - Help Section
ECHO.
ECHO 1- In order to search for multiples IPs, Hashes or Domains, you use comma "," between values or just space " ", Example:
ECHO.
ECHO + IPs 
ECHO 10.0.0.100 , 10.0.0.101 , 10.0.0.102
ECHO.
ECHO Or
ECHO.
ECHO 10.0.0.100 10.0.0.101 10.0.0.102
ECHO.
ECHO + Domains
ECHO google.com , bing.com 
ECHO.
ECHO + Hashes
ECHO 1079a055f110d54ba12f08bd6b671f6c , f0d01cda4b9b4db889a55abef4b50f180ee138f1 
ECHO.
PAUSE
GOTO MENU



:: A - API Key Change
:VERIFYVTAPI
CLS
ECHO          A - API Key Change
ECHO.
SET /p ApiKeyValue=Paste your Virus Total API Key: 
IF "%ApiKeyValue%"=="0" GOTO MENU 
IF "%ApiKeyValue:~63%"=="" (
    ECHO.
    ECHO Type a valid API value.   This one doesn`t has 64 characters.
    ECHO.
    ECHO.
    PAUSE
    GOTO VERIFYVTAPI
)
ECHO %ApiKeyValue% > "Data\ApiKey\ApiKey.txt"
ECHO.
ECHO Success "%ApiKeyValue%" was saved to "\Data\ApiKey\ApiKey.txt"
ECHO.
ECHO.
PAUSE
GOTO INITIALSETTINGS



:: D - API Key Daily Quota
:APIDAILYQUOTA
CLS
ECHO          D - API Key Daily Quota
ECHO.
ECHO.
Data\vt.exe user -k %ApiKey% --include=apikey,email,quotas.api_requests_daily.used,status %ApiKey%
ECHO.
ECHO.
PAUSE
GOTO MENU