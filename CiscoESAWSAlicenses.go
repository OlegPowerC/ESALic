package main

import (
	fp "./parser2"
	"webnms/snmp/consts"
	"webnms/snmp/msg"
	"fmt"
	"os"
	"webnms/snmp/util"
	"encoding/xml"
	SNMPd "./snmpcommondata"
	"webnms/snmp"
	"strconv"
)

const LICENSES_INDEXES = ".1.3.6.1.4.1.15497.1.1.1.12.1.1"	//Alarm Major for Gateway
const LICENSES_DESCRIPTIONS = ".1.3.6.1.4.1.15497.1.1.1.12.1.2"	//Alarm Minor for Gateway
const LICENSES_PERPETUAL_OR_NOT = ".1.3.6.1.4.1.15497.1.1.1.12.1.3"		//Alarm Warning for Gateway
const LICENSES_EXPIRED_TIME_SECS = ".1.3.6.1.4.1.15497.1.1.1.12.1.4"	//Alarm Major

type result struct {
	Channel string      `xml:"channel"`
	Value string `xml:"value"`
	Unit string `xml:"unit"`
	CustomUnit string `xml:"CustomUnit"`
}

type prtgbody struct {
	XMLName xml.Name `xml:"prtg"`
	TextField string `xml:"text"`
	Res []result `xml:"result"`
}

type cu struct {
	ip string				//IP адрес
	SNMPdata SNMPd.SNMPparams
}

type Licenses struct{
	Index int
	Description string
	Perpetual bool
	ExpireSecs int
	ExpireDays int
}



func main() {
	var rd1 []result
	var err error
	var avacu cu
	Lic := make([]Licenses,0)

	var usage = "ciscoportdata -v version(v1,v2, v3) [-c community] \n" +
		"[-p port] [-r retries] [-t timeout]" + "\n" +
		"if snmpv3: [-u username in current version of ESA/WSA it is v3get] [-n contextname] [-a authprotocol (MD5/SHA)] [-w authpassword]" + "\n" +
		"[-pp privprotocol (DES/3DES/AES-128/AES-192/AES-256)] [-s privpassword] [-e engineID]"+"\n"+
		"-cm WSA/ESA address\n"+
		"-rus Russian language"


	//Проверка полученых флагов
	if err = fp.ValidateFlags(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, "Usage:", "\n"+usage)
		os.Exit(1)
	}



	avacu.ip = fp.CallManagerIp
	avacu.SNMPdata.SnmpVersion = fp.Version
	avacu.SNMPdata.SnmpCommunity = fp.Community
	avacu.SNMPdata.SnmpUsername = fp.UserName
	avacu.SNMPdata.SnmpAuthpass = fp.AuthPassword
	avacu.SNMPdata.SnmpPrivpass = fp.PrivPassword
	avacu.SNMPdata.SnmpAuthProtocol = fp.AuthProtocol
	avacu.SNMPdata.SnmpPrivProtocol = fp.PrivProtocol
	avacu.SNMPdata.SnmpSecurityLevel = fp.GetSecurityLevel()

	var SNMPcses SNMPd.SNMPcurrenPointers

	SNMPcses.Api = snmp.NewSnmpAPI()
	SNMPcses.Ses = snmp.NewSnmpSession(SNMPcses.Api)
	SNMPcses.Api.SetDebug(fp.Debug)

	//Create UDP options and set it on the SnmpSession
	SNMPcses.Udp = snmp.NewUDPProtocolOptions()
	SNMPcses.Udp.SetRemoteHost(avacu.ip)

	SNMPcses.Udp.SetRemotePort(fp.Port)
	SNMPcses.Ses.SetProtocolOptions(SNMPcses.Udp)

	//Open a new SnmpSession
	if err := SNMPcses.Ses.Open(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer SNMPcses.Ses.Close() //Close the SnmpSession in any case
	defer SNMPcses.Api.Close() //Close the SnmpAPI in any case

	SNMPcses.Mes = msg.NewSnmpMessage()


	if avacu.SNMPdata.SnmpVersion == consts.Version3 {
		err := util.Init_V3_LCD(SNMPcses.Ses,
			SNMPcses.Udp,
			avacu.SNMPdata.SnmpUsername,
			avacu.SNMPdata.EngineID, //validation should be done
			avacu.SNMPdata.SnmpAuthProtocol,
			avacu.SNMPdata.SnmpAuthpass,
			avacu.SNMPdata.SnmpPrivProtocol,
			avacu.SNMPdata.SnmpPrivpass,
			false, //Validate User
		)
		if err != nil {
			fmt.Println("Error when call Init_V3_LCD")
			fmt.Fprintln(os.Stderr, err)

			os.Exit(1)
		}

		SNMPcses.Mes.SetUserName(avacu.SNMPdata.SnmpUsername)
		SNMPcses.Mes.SetContextName(avacu.SNMPdata.SnmpContextName)
		//Set the security level for the msg.
		SNMPcses.Mes.SetSecurityLevel(avacu.SNMPdata.SnmpSecurityLevel)

	}


	SNMPcses.Mes.SetVersion(avacu.SNMPdata.SnmpVersion)
	SNMPcses.Mes.SetCommunity(avacu.SNMPdata.SnmpCommunity)
	SNMPcses.Mes.SetCommand(consts.GetNextRequest)
	SNMPcses.Mes.SetRetries(fp.Retries)
	SNMPcses.Mes.SetTimeout(fp.Timeout)

	alltextmessage := ""

	LicenseIndexes := SNMPd.GetSuffixes(&SNMPcses,LICENSES_INDEXES)

	for _,LicenseIndex := range LicenseIndexes{
		_,Descr := SNMPd.GetSingleData(&SNMPcses,LICENSES_DESCRIPTIONS+"."+LicenseIndex.Value)
		iLicIndex,_ := strconv.Atoi(LicenseIndex.Value)
		_,Perpetual := SNMPd.GetSingleData(&SNMPcses,LICENSES_PERPETUAL_OR_NOT+"."+LicenseIndex.Value)
		PerpInt,_ := strconv.Atoi(Perpetual)
		PerpBool := false
		if PerpInt == 1{
			PerpBool = true
		}else {
			PerpBool = false
		}
		_,Licenseexpired := SNMPd.GetSingleData(&SNMPcses,LICENSES_EXPIRED_TIME_SECS+"."+LicenseIndex.Value)
		LicExpiredSecInt,_ := strconv.Atoi(Licenseexpired)
		Lic = append(Lic,Licenses{Index:iLicIndex,Description:Descr,Perpetual:PerpBool,ExpireSecs:LicExpiredSecInt,ExpireDays:(LicExpiredSecInt/86400)})
	}

	for _,LicRow := range Lic{
		if LicRow.Perpetual{
			rd1 = append(rd1,result{Channel:LicRow.Description + " PERPETUAL", Value:strconv.Itoa(LicRow.ExpireDays),Unit:"Custom",CustomUnit:"days"})
		}else {
			rd1 = append(rd1,result{Channel:LicRow.Description, Value:strconv.Itoa(LicRow.ExpireDays),Unit:"Custom",CustomUnit:"days"})
		}
	}

	mt1 := &prtgbody{TextField:alltextmessage,Res: rd1}
	bolB, _ := xml.Marshal(mt1)
	fmt.Println(string(bolB))
}



