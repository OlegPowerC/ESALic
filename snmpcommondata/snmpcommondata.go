package snmpcommondata

import (
	WNMSconsts "webnms/snmp/consts"
	"fmt"
	"webnms/snmp/snmpvar"
	"webnms/snmp"
	"webnms/snmp/msg"
	"webnms/snmp/engine/transport/udp"
	"time"
	"os"
	"pro1/webnms/snmp/consts"
)

type SNMPcurrenPointers struct {
	Udp *udp.UDPProtocolOptions
	Mes msg.SnmpMessage
	Ses *snmp.SnmpSession
	Api *snmp.SnmpAPI
}

type SNMPparams struct {
	SnmpVersion WNMSconsts.Version
	SnmpCommunity string
	SnmpUsername string
	SnmpAuthpass string
	SnmpPrivpass string
	SnmpAuthProtocol WNMSconsts.AuthProtocol
	SnmpPrivProtocol WNMSconsts.PrivProtocol
	SnmpContextName string
	EngineID []byte
	SnmpSecurityLevel WNMSconsts.SecurityLevel
}

type WalkResult struct {
	ValType byte
	Value string
}

func GetSuffixes(SNMPcses *SNMPcurrenPointers,oidx string) []WalkResult{
	retval20 := make([]WalkResult,0)

	SNMPcses.Mes.SetCommand(WNMSconsts.GetNextRequest)
	SNMPcses.Mes.SetAuthenticationFailure(false)
	SNMPcses.Mes.SetEnqueue(false)

	SNMPcses.Mes.SetRetries(3)
	SNMPcses.Mes.SetTimeout(1000)
	SNMPcses.Mes.SetTimeExpire(1000)


	oid := snmpvar.NewSnmpOID(oidx)
	rootOID := oid
	newMsg := SNMPcses.Mes.CopyWithoutVarBinds()
	newMsg.AddNull(*oid)
	SNMPcses.Mes = *newMsg

	time.Sleep(1)
	for{
		if lresp, err := SNMPcses.Ses.SyncSend(SNMPcses.Mes); err != nil {
			fmt.Println("ERR",os.Stderr, err)
			return nil
		}else {

			if lresp.ErrorStatus() != 0 {
				fmt.Println("ERR",lresp.ErrorString())
				break
			}
			if !(inSubTree(rootOID.Value(), *lresp)) {

				break
			} else {



				var lt byte
				for _,alresp := range lresp.VarBinds(){
					lt = alresp.Variable().Type()
					switch(lt){
					case consts.Counter64 :
						retval20 = append(retval20,WalkResult{lt,alresp.Variable().String()})
						;break
					case consts.Counter :
						retval20 = append(retval20,WalkResult{lt,alresp.Variable().String()})
						;break
					case consts.Gauge :
						retval20 = append(retval20,WalkResult{lt,alresp.Variable().String()})
						;break
					case consts.Integer :
						retval20 = append(retval20,WalkResult{lt,alresp.Variable().String()})
						;break
					case consts.OctetString :
						retval20 = append(retval20,WalkResult{lt,alresp.Variable().String()})
						;break
					default:
						break
					}
				}

				oid := lresp.ObjectIDAt(0)
				newMsg := SNMPcses.Mes.CopyWithoutVarBinds()
				if oid != nil {
					newMsg.AddNull(*oid)
				}
				SNMPcses.Mes = *newMsg
			}
		}
	}
	return retval20
}

//Получение данных
func GetSingleData(SNMPcses *SNMPcurrenPointers,oidx string) (byte,string){
	SNMPcses.Mes.SetCommand(WNMSconsts.GetRequest)
	SNMPcses.Mes.SetAuthenticationFailure(false)
	SNMPcses.Mes.SetEnqueue(false)

	SNMPcses.Mes.SetRetries(3)
	SNMPcses.Mes.SetTimeout(1000)
	SNMPcses.Mes.SetTimeExpire(1000)

	oid := snmpvar.NewSnmpOID(oidx)
	newMsg := SNMPcses.Mes.CopyWithoutVarBinds()
	newMsg.AddNull(*oid)
	SNMPcses.Mes = *newMsg

	retval := ""
	var lt byte

	time.Sleep(1)
	if lresp, err := SNMPcses.Ses.SyncSend(SNMPcses.Mes); err != nil {
		fmt.Println("ERR",os.Stderr, err)
		return 0,""
	}else {


		if lresp.ErrorStatus() != 0 {
			fmt.Println("ERR",lresp.ErrorString())
			return 0,""
		}

		for _,alresp := range lresp.VarBinds(){
			lt = alresp.Variable().Type()
			switch(lt){
			case consts.Counter64 :
				retval = alresp.Variable().String()
				;break
			case consts.Counter :
				retval = alresp.Variable().String()
				;break
			case consts.Gauge :
				retval = alresp.Variable().String()
				;break
			case consts.Integer :
				retval = alresp.Variable().String()
				;break
			case consts.OctetString :
				retval = alresp.Variable().String()
				;break
			default:
				break
			}
		}

	}
	return lt,retval
}

//Check if first varbind oid has rootoid as an ancestor in MIB tree
func inSubTree(root []uint32, pdu msg.SnmpMessage) bool {

	oid := pdu.ObjectIDAt(0)
	if oid == nil {
		return false
	}
	oidArray := oid.Value()
	if len(oidArray) < len(root) {
		return false
	}

	for i, v := range root {
		if oidArray[i] != v {
			return false
		}
	}
	return true
}