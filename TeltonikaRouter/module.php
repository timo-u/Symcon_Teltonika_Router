<?php

declare(strict_types=1);
class TeltonikaRouter extends IPSModule
{
    public function Create()
    {
        //Never delete this line!
        parent::Create();

        $this->RegisterVariableProfiles();
        $this->RegisterPropertyBoolean('Active', true);
        $this->RegisterPropertyString('Host', '192.168.2.1');
        $this->RegisterPropertyInteger('Port', 443);
        $this->RegisterPropertyString('Username', '');
        $this->RegisterPropertyString('Password', '');

        $this->RegisterPropertyInteger('Timeout', 1);
        $this->RegisterPropertyInteger('UpdateInterval', 60);

        $this->RegisterPropertyBoolean('ShowModemInfomation', true);
        $this->RegisterPropertyBoolean('ShowFailoverInfomation', false);
        $this->RegisterPropertyBoolean('ShowTrafficInfomation', false);
        $this->RegisterPropertyBoolean('ShowCcid', false);

        $this->RegisterPropertyBoolean('Ssl', true);
        $this->RegisterPropertyBoolean('VerifyHost', false);
        $this->RegisterPropertyBoolean('VerifyPeer', false);

        $this->RegisterTimer('Update', $this->ReadPropertyInteger('UpdateInterval') * 1000, 'TR_UpdateValues($_IPS[\'TARGET\']);');

        $this->RegisterAttributeInteger("FirmwareUpdateStep", 0);


    }

    public function ApplyChanges()
    {
        //Never delete this line!
        parent::ApplyChanges();
        $this->Maintain();

        $this->SetValue('IpAddress', $this->ReadPropertyString('Host'));
        $this->SetTimerInterval('Update', $this->ReadPropertyInteger('UpdateInterval') * 1000);
    }

    public function RequestAction($Ident, $Value)
    {
        // RequestAction wird genutzt um die interenen Funtionen nach außen zu verstecken
        switch ($Ident) {
            case "EnableLogging":
                $this->EnableLogging();
                break;
            case "DisableLogging":
                $this->DisableLogging();
                break;
            case 'Reboot':
                $this->Reboot();
                break;
            case "Login":
                $this->Login(true);
                break;
            case "UpdateValues":
                $this->UpdateValues();
                break;
            case "FirmwareUpdate":
                $this->FirmwareUpdate();
                break;


        }
    }



    private function EnableLogging()
    {
        $this->Logging(true);
    }

    private function DisableLogging()
    {
        $this->Logging(false);
    }
    private function Logging(bool $enabled)
    {
        $archiveId = IPS_GetInstanceListByModuleID('{43192F0B-135B-4CE7-A0A7-1475603F3060}')[0];

        $arr = [    'Connection',
                    'Ping',
                    'Firmware',
                    'Uptime',
                    'Signal0', 'TxGBytes0', 'RxGBytes0', 'Temperature0', 'Band0', 'Provider0',
                    'Signal1', 'TxGBytes1', 'RxGBytes1', 'Temperature1', 'Band1', 'Provider1', 
                    'Load'
                ];

        foreach ($arr as &$ident) {
            $id = @$this->GetIDForIdent($ident);

            if ($id == 0) {
                continue;
            }
            if ($enabled) {
                AC_SetLoggingStatus($archiveId, $id, true);
                AC_SetAggregationType($archiveId, $id, 0); // 0 Standard, 1 Zähler
                AC_SetGraphStatus($archiveId, $id, true);
            } else {
                AC_SetGraphStatus($archiveId, $id, false);
                AC_SetLoggingStatus($archiveId, $id, false);
            }

        }

        IPS_ApplyChanges($archiveId);
    }

    public function GetRouterConfiguratationPage()
    {
        $url = $this->ReadPropertyString('Host').":".$this->ReadPropertyInteger('Port');

        if ($this->ReadPropertyBoolean('Ssl')) {
            $url = "https://".$url;
        } else {
            $url = "http://".$url;
        }
        return $url;

    }

    public function Login(bool $force = false)
    {
        if (!$this->ReadPropertyBoolean('Active')) {
            return false;
        }

        if ($this->GetBuffer('Authentication') == 'failed' && !$force) {
            $this->SendDebug(__FUNCTION__, 'Authentication has failed - Login is blocked!', 0);
            return false;
        }


        $this->SendDebug(__FUNCTION__, 'Try to log in', 0);

        $username = $this->ReadPropertyString('Username');
        $password = $this->ReadPropertyString('Password');
        $url = $this->ReadPropertyString('Host').":".$this->ReadPropertyInteger('Port');

        if ($this->ReadPropertyBoolean('Ssl')) {
            $url = "https://".$url;
        } else {
            $url = "http://".$url;
        }


        $post = json_encode(array( "username" => $username ,"password" => $password));

        if ($this->ReadPropertyBoolean('VerifyHost')) {
            $verifyhost = 2;
        } else {
            $verifyhost = 0;
        }

        $curl = curl_init();


        curl_setopt($curl, CURLOPT_URL, $url.'/api/login');
        curl_setopt($curl, CURLOPT_CUSTOMREQUEST, 'POST');
        curl_setopt($curl, CURLOPT_POSTFIELDS, $post);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_CONNECTTIMEOUT, 2);
        curl_setopt($curl, CURLOPT_TIMEOUT, $this->ReadPropertyInteger('Timeout'));
        curl_setopt($curl, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
        curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, $verifyhost);
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, $this->ReadPropertyBoolean('VerifyPeer'));
        curl_setopt($curl, CURLOPT_HTTPHEADER, array('Content-Type: application/json'));



        $response = curl_exec($curl);
        $err = curl_error($curl);

        $this->SendDebug(__FUNCTION__, 'Response:' . $response, 0);

        curl_close($curl);
        if ($err) {
            $this->SetStatus(201);
            $this->SendDebug(__FUNCTION__, 'Error:' . $err, 0);
            $this->SetBuffer('SessionId', '');
            $this->SetValue('Connection', false);
            return false;
        }

        $data = json_decode($response, false);


        $success = ($data->success);

        if ($success) {
            if (property_exists($data->data, 'token')) {
                $this->SetStatus(102);
                $this->SetBuffer('SessionId', $data->data->token);
                $this->SetBuffer('Authentication', '');
                $this->SetValue('Connection', true);
            }

            if (property_exists($data, 'ubus_rpc_session')) {
                $this->SetBuffer('Authentication', 'failed');
                $this->SendDebug(__FUNCTION__, 'Falsche API-Version! Update erforderlich', 0);
                $this->SetValue('Connection', false);
                $this->SetValue('Firmware', "< 7.6.x");
                $this->SetStatus(203); // Version Conflict
                $success = false;
            }

        } else {
            $this->SendDebug(__FUNCTION__, 'Authentication failed', 0);
            $this->SendDebug(__FUNCTION__, 'Code:' . $data->errors[0]->code, 0);
            if ($data->errors[0]->code == 120) {
                $this->SendDebug(__FUNCTION__, 'Login Failed.', 0);
            }

            $this->LogMessage('Teltonika Router =>Login() => Code:' . $data->errors[0]->code, KL_ERROR);

            $this->SetBuffer('Authentication', 'failed');
            $this->SetValue('Connection', false);
            $this->SetStatus(202); // Authentication failed
        }

        return $success;
    }
    public function ApiCall(array $parameter)
    {
        /*

        $parameter = array( "method"=>"get",
                            "timeout"=>1, /* übschchreibt das in der Instanz gesetze Timeout. z.B. wichtig bei Updates, die mit der voreingestellen Zeit nicht auskommen.
                            "subpath" => "/webapi/entry.cgi",
                            "getparameter"=> array( "id=1")
                            );

        */

        if ($parameter == null || !array_key_exists('subpath', $parameter)) {
            $this->SendDebug(__FUNCTION__, 'Fehlerhafte Parameter', 0);
            return false;
        }

        if (array_key_exists('method', $parameter)) {
            $method = strtoupper($parameter['method']);

            if (!($method == "GET" || $method == "POST" || $method == "PUT" || $method == "DELETE")) {
                $this->SendDebug(__FUNCTION__, 'Methode nicht erlaubt', 0);
                return false;
            }
        } else {
            $method = "GET"; // Standard Methode
        }

        $postfield = "";
        if (array_key_exists('postfield', $parameter)) {
            $postfield = $parameter['postfield'];
        }


        $timeout = $this->ReadPropertyInteger('Timeout'); // Standard-Timeout setzen
        if (array_key_exists('timeout', $parameter)) {
            $timeout = $parameter['timeout'];
        }

        $subpath = $parameter['subpath'];


        $GetParameter = "";
        if (array_key_exists('getparameter', $parameter)) {
            $GetParameter = $parameter['getparameter'];
        }

        if (!$this->ReadPropertyBoolean('Active')) {
            return false;
        }


        // Überprüfung ob sessionkey vorhanden ist => Sonst Login
        $sessionId = $this->GetBuffer('SessionId');
        $this->SendDebug(__FUNCTION__, 'SessionId: '.$sessionId, 0);
        if ($sessionId == "") {
            $this->SendDebug(__FUNCTION__, '->Login', 0);
            if ($this->Login()) {
                $this->SendDebug(__FUNCTION__, 'Login Succsessfull', 0);
                $sessionId = $this->GetBuffer('SessionId');
            } else {
                return false; // wenn login fehlerhaft abbrechen.

            }
        }

        if ($this->ReadPropertyBoolean('VerifyHost')) {
            $verifyhost = 2;
        } else {
            $verifyhost = 0;
        }

        $url = $this->ReadPropertyString('Host').":".$this->ReadPropertyInteger('Port');

        if ($this->ReadPropertyBoolean('Ssl')) {
            $url = "https://".$url;
        } else {
            $url = "http://".$url;
        }

        if ($GetParameter != "") {
            $url = $url.$subpath. "?".  implode("&", $GetParameter);
        } else {
            $url = $url.$subpath;
        }

        $this->SendDebug(__FUNCTION__, 'URL:' . $url. ' Method:' . $method, 0);
        $this->SendDebug(__FUNCTION__, 'SessionID:' . $sessionId, 0);

        $curl = curl_init();

        curl_setopt($curl, CURLOPT_URL, $url);
        curl_setopt($curl, CURLOPT_CUSTOMREQUEST, $method);

        if ($postfield != "") {
            curl_setopt($curl, CURLOPT_POSTFIELDS, $postfield);
        }
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_CONNECTTIMEOUT, 2);
        curl_setopt($curl, CURLOPT_TIMEOUT, $timeout);
        curl_setopt($curl, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
        curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, $verifyhost);
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, $this->ReadPropertyBoolean('VerifyPeer'));
        curl_setopt($curl, CURLOPT_HTTPHEADER, array('Content-Type: application/json',"Authorization: Bearer $sessionId"));


        $response = curl_exec($curl);
        $err = curl_error($curl);
        $httpcode = curl_getinfo($curl, CURLINFO_HTTP_CODE);

        $this->SendDebug(__FUNCTION__, 'CURL Response: ' . $response, 0);
        $this->SendDebug(__FUNCTION__, 'CURL Statuscode: ' . $httpcode, 0);

        curl_close($curl);

        if ($err) {
            $this->SendDebug(__FUNCTION__, 'CURL Error: ' . $err, 0);
            return false;
        }

        if ($response == null || $response == "") {
            return false;
        }


        $data = json_decode($response);

        if (property_exists($data, 'errors') && property_exists($data->errors[0], 'code')) {
            if ($data->errors[0]->code == 123) { // Invalid session
                $this->SetBuffer('SessionId', ""); // Session-ID entfernen, dadurch wird beim nächsten versuch neu angemeldet
                $this->SendDebug(__FUNCTION__, 'Invalid session', 0);
                // wenn API aufruf an abgelaufenem Token gescheitert
                if ($this->Login()) { 	//Login
                    return $this->ApiCall($parameter); //Funktion rekusiv aufrufen.
                }

                return false;

            }
			if ($data->errors[0]->code == 121) { // Invalid session
                $this->SendDebug(__FUNCTION__, 'Login failed for any reason', 0);
                if(property_exists($data->errors[0], 'error'))
				{
					$this->SendDebug(__FUNCTION__, 'Error: '. $data->errors[0]->error, 0);
				}
				$this->SendDebug(__FUNCTION__, 'From firmware version 7.12 on RUTX family devices, HTTPS is enforced by default.', 0);
                $this->SetStatus(204); // Login failed for any reason
				return false;

            }
        }

        $data = json_encode(array("apidata" => $data, "apierror" => $err, "apiparameter" => $parameter, "url" => $url ));

        $this->SendDebug(__FUNCTION__, 'Response:' . $data, 0);
        $this->SetValue('Connection', true);
        $this->SetStatus(102); //Staus: Aktiv
        return $data;
    }


    public function UpdateValues()
    {
        $this->Maintain();

        $pingresponse = @Sys_Ping($this->ReadPropertyString('Host'), $this->ReadPropertyInteger('Timeout') * 1000);
        $this->SetValue('Ping', $pingresponse);

        if (!$pingresponse) { // Wenn Ping fehlschlägt keine weiteren Abfragen
            $this->SetStatus(104); //Staus: Offline/inaktiv
            $this->SetValue('Connection', false);
            return;
        }


        $parameter = array( "method" => "get",
                            "subpath" => "/api/system/device/status",
                            "getparameter" => array() );
        $data =  $this->ApiCall($parameter);

        if ($data != false) {
            $data = json_decode($data);
            if (property_exists($data, 'apidata') && property_exists($data->apidata, 'data')) {
                $this->SendDebug(__FUNCTION__, 'Firmware: ' . $data->apidata->data->static->fw_version, 0);
                $this->SendDebug(__FUNCTION__, 'Device_Name: ' . $data->apidata->data->static->device_name, 0);
                $this->SendDebug(__FUNCTION__, 'Serial: ' . $data->apidata->data->mnfinfo->serial, 0);

                $this->SetValue('Firmware', $data->apidata->data->static->fw_version);
                $this->SetValue('DeviceName', $data->apidata->data->static->device_name);
                $this->SetValue('Serial', $data->apidata->data->mnfinfo->serial);
            }
        }



        if ($this->ReadPropertyBoolean('ShowModemInfomation')) {

            $parameter = array( "method" => "get",
                                "subpath" => "/api/modems/status",
                                "getparameter" => array() );
            $data =  $this->ApiCall($parameter);

            if ($data != false) {
                $data = json_decode($data);

                if (property_exists($data, 'apidata') && property_exists($data->apidata, 'data')) {

                    $this->SendDebug(__FUNCTION__, 'Data: ' . json_encode($data->apidata->data), 0);
                    $modemnumber = 0;

                    foreach ($data->apidata->data as &$modemData) {

                        $modemname = $this->Translate('Modem').' '.$modemnumber + 1 .' ';


                        $this->MaintainVariable('Provider'.$modemnumber, $modemname. $this->Translate('Provider'), 3, '', $modemnumber * 10 + 31, true);
                        $this->MaintainVariable('Band'.$modemnumber, $modemname. $this->Translate('Band'), 3, '', $modemnumber * 10 + 32, true);
                        $this->MaintainVariable('Signal'.$modemnumber, $modemname. $this->Translate('Signal (RSSI)'), 1, 'TR_Signal', $modemnumber * 10 + 33, true);
                        $this->MaintainVariable('TxGBytes'.$modemnumber, $modemname. $this->Translate('Send GBytes'), 2, 'TR_Traffic', $modemnumber * 10 + 40, $this->ReadPropertyBoolean('ShowTrafficInfomation'));
                        $this->MaintainVariable('RxGBytes'.$modemnumber, $modemname. $this->Translate('Receved GBytes'), 2, 'TR_Traffic', $modemnumber * 10 + 41, $this->ReadPropertyBoolean('ShowTrafficInfomation'));
                        $this->MaintainVariable('Temperature'.$modemnumber, $modemname. $this->Translate('Temperature'), 1, 'TR_Temperature', $modemnumber * 10 + 50, true);
                        $this->MaintainVariable('CCID'.$modemnumber, $modemname. $this->Translate('CCID'), 3, '', $modemnumber * 10 + 32, $this->ReadPropertyBoolean('ShowCcid'));

                        $this->SendDebug(__FUNCTION__, 'Modem: '.$modemnumber.' Provider: ' . $modemData->provider, 0);
                        $this->SendDebug(__FUNCTION__, 'Modem: '.$modemnumber.' Signal: ' . $modemData->signal, 0);
                        $this->SendDebug(__FUNCTION__, 'Modem: '.$modemnumber.' Band: ' . $modemData->band, 0);
                        $this->SendDebug(__FUNCTION__, 'Modem: '.$modemnumber.' CCID: ' . $modemData->iccid, 0);

                        $this->SetValue('Provider'.$modemnumber, $modemData->provider);
                        if ($modemData->signal != "N/A") {
                            $this->SetValue('Signal'.$modemnumber, $modemData->signal);
                        }

                        $this->SetValue('Band'.$modemnumber, $modemData->band);
                        if ($this->ReadPropertyBoolean('ShowCcid')) {
                            $this->SetValue('CCID'.$modemnumber, $modemData->iccid);
                        }
                        if ($this->ReadPropertyBoolean('ShowTrafficInfomation')) {
                            $this->SetValue('TxGBytes'.$modemnumber, $modemData->txbytes / 1073741824); // txbytes/1024/1024/1024 Umrechnung Byte auf GB
                            $this->SetValue('RxGBytes'.$modemnumber, $modemData->rxbytes / 1073741824);
                        }
                        $this->SetValue('Temperature'.$modemnumber, $modemData->temperature);

						$modemnumber = $modemnumber+1;
                    }
                }
            }
        }

        $parameter = array( "method" => "get",
                            "subpath" => "/api/system/device/usage/status",
                            "getparameter" => array( "data=uptime_seconds,load"));
        // Abfrage auf diese Parameter begrenzt da Router sonst lange benötigt um die Daten zurückzugeben


        $data =  $this->ApiCall($parameter);

        if ($data != false) {
            $data = json_decode($data);

            if (property_exists($data, 'apidata') && property_exists($data->apidata, 'data')) {

                $this->SendDebug(__FUNCTION__, 'Load 1min: ' . $data->apidata->data->load->min1. " %", 0);
                $this->SendDebug(__FUNCTION__, 'Uptime: ' . $data->apidata->data->uptime_seconds . " s", 0);
                $this->SetValue('Load', $data->apidata->data->load->min1 * 100);
                $this->SetValue('Uptime', $data->apidata->data->uptime_seconds / 3600);
            }
        }


        if ($this->ReadPropertyBoolean('ShowFailoverInfomation')) {
            $parameter = array( "method" => "get",
                                "subpath" => "/api/failover/status",
                                "getparameter" => array() );
            $data =  $this->ApiCall($parameter);

            if ($data != false) {
                $data = json_decode($data);
                if (property_exists($data, 'apidata') && property_exists($data->apidata, 'data')) {
                    $activeInterface = "-";
                    foreach ($data->apidata->data as $key =>  &$failoverItem) {

                        if ($failoverItem->status == "online") {
                            $activeInterface = $key ;
                        }

                    }
                    $this->SendDebug(__FUNCTION__, 'Active Interface: ' . $activeInterface, 0);
                    $this->SetValue('FailoverActiveInterface', $this->Translate($activeInterface));
                }
            }
        }


    }

    private function Reboot()
    {

        $parameter = array( "method" => "POST",
                            "subpath" => "/api/system/actions/reboot",
                            "getparameter" => array() );
        $data =  $this->ApiCall($parameter);
        if ($data != false) {
            $this->SendDebug(__FUNCTION__, "DATA: ". $data, 0);
            $data = json_decode($data);
            if ($data->apidata->success) {
                echo "Neustart erfolgreich ausgelöst";
            }
            return $data->apidata->success;

        }
    }

    public function FirmwareUpdate()
    {
        $firmwareUpdateStep = $this->ReadAttributeInteger("FirmwareUpdateStep");


        if ($firmwareUpdateStep == 0) {
            $parameter = array( "method" => "GET",
                                "timeout" => 30, //Anfrage benötigt längeres Timeout
                                "subpath" => "/api/firmware/device/updates/status",
                                "getparameter" => array() );
            $data =  $this->ApiCall($parameter);

            if ($data == false) {
                return;
            } // Abbruch
            $this->SendDebug(__FUNCTION__, "DATA: ". $data, 0);
            $data = json_decode($data);

            if (!property_exists($data->apidata->data, 'device') || !property_exists($data->apidata->data->device, 'version')) {
                echo "Es kann nicht auf eine aktuelle Firmware geprüft werden.\r\n";
                return;  // Abbruch Firmware aktuell ist.
            }

            if ($data->apidata->data->device->version == "newest") {
                echo "Firmware ist aktuell\r\n";
                return;  // Abbruch Firmware aktuell ist.
            }

            if ($data->apidata->data->device->version != "newest") {
                echo "Neue Firmware vorhanden: (". $data->apidata->data->device->version . ")\r\n";
                $this->WriteAttributeInteger("FirmwareUpdateStep", 1);
                $firmwareUpdateStep = 1;
            }
        }


        // Download der Firmware anstroßen
        if ($firmwareUpdateStep == 1) {
            $parameter = array( "method" => "POST",
                                "timeout" => 30, //Anfrage benötigt längeres Timeout
                                "subpath" => "/api/firmware/actions/fota_download",
                                "getparameter" => array() );
            $data =  $this->ApiCall($parameter);
            //$this->SendDebug(__FUNCTION__, 'Response:' . $data, 0);
            if ($data == false) {
                return;
            } // Abbruch

            $this->SendDebug(__FUNCTION__, "DATA: ". $data, 0);
            $data = json_decode($data);

            if (!$data->apidata->success) {
                echo "Firmware-Download nicht erfolgreich gestartet.\r\n";
                return;
            }
            $this->WriteAttributeInteger("FirmwareUpdateStep", 2);
            $firmwareUpdateStep = 2;

        }


        // Prüfen ob Firmware heruntergeladen wurde
        if ($firmwareUpdateStep == 2) {
            $parameter = array( "method" => "GET",
                                "timeout" => 30, //Anfrage benötigt längeres Timeout
                                "subpath" => "/api/firmware/device/progress/status",
                                "getparameter" => array() );
            $data =  $this->ApiCall($parameter);
            //$this->SendDebug(__FUNCTION__, 'Response:' . $data, 0);
            if ($data == false) {
                return;
            } // Abbruch
            $this->SendDebug(__FUNCTION__, "DATA: ". $data, 0);
            $data = json_decode($data);

            if ($data->apidata->data->process == "started") {
                echo "Firmware-Download gestartet (". $data->apidata->data->percents . "%)\r\n";
                return;  // Abbruch wenn update nur im Zustand gestartet mit Ausgabe von Prozentwert
            }
            if ($data->apidata->data->process != "succeeded") {
                echo "Firmware-Download noch nicht beendet\r\n";
                return;  // Abbruch wenn update nicht vollständig
            }
            $this->WriteAttributeInteger("FirmwareUpdateStep", 3);
            $firmwareUpdateStep = 3;
        }


        if ($firmwareUpdateStep == 3) {

            $postfield = json_encode(array("data" => array("keep_settings" => "1")));
            $parameter = array( "method" => "POST",
                                "postfield" => $postfield,
                                "timeout" => 30, //Anfrage benötigt längeres Timeout
                                "subpath" => "/api/firmware/actions/upgrade",
                                "getparameter" => array() );
            $data =  $this->ApiCall($parameter);
            //$this->SendDebug(__FUNCTION__, 'Response:' . $data, 0);
            if ($data == false) {
                return;
            } // Abbruch

            $this->SendDebug(__FUNCTION__, "DATA: ". $data, 0);
            $data = json_decode($data);

            if ($data->apidata->success) {
                echo "Firmware-Upgrade erfolgreich gestartet.\r\n";
                $this->WriteAttributeInteger("FirmwareUpdateStep", 0);
                return;
            } else {
                echo "Firmware-Upgrade start fehlerhaft.\r\n";
                return;
            }

        }
    }

    public function AddPortForwarding(array $postdata)
    {
        $postfield = json_encode(array("data" => $postdata,));

        $parameter = array( "method" => "POST",
                            "postfield" => $postfield,
                            "subpath" => "/api/firewall/port_forwards/config",
                            "getparameter" => array()
                                   );

        $response = ($this->ApiCall($parameter));
        $data = json_decode($response);

        if ($data->apidata->success) {
            $this->SendDebug(__FUNCTION__, "Add Rule ".$postdata['name']. " erfolgreich", 0);
        }
        return $data;
    }

    public function UpdatePortForwarding(string $id, array $data)
    {

        $defaultValues = array("id" => $id );
        $postdata = array_merge($defaultValues, $data);

        $postfield = json_encode(array("data" => array($postdata),));

        $parameter = array( "method" => "PUT",
                            "postfield" => $postfield,
                            "subpath" => "/api/firewall/port_forwards/config",
                            "getparameter" => array()
                                   );

        $response = ($this->ApiCall($parameter));
        $data = json_decode($response);

        if ($data->apidata->success) {
            $this->SendDebug(__FUNCTION__, "Update Rule ".$postdata['name']. " erfolgreich", 0);
        }

        return $data;
    }

    public function DeletePortForwarding(string $id)
    {
        $postfield = json_encode(array("data" => array($id),));

        $parameter = array( "method" => "DELETE",
                            "postfield" => $postfield,
                            "subpath" => "/api/firewall/port_forwards/config",
                            "getparameter" => array()
                                   );

        $response = ($this->ApiCall($parameter));
        $data = json_decode($response);

        if ($data->apidata->success) {
            $this->SendDebug(__FUNCTION__, "Delete Rule ID:".$id.  " erfolgreich", 0);
        }

        return $data;
    }


    public function GetPortForwardings()
    {
        $parameter = array( "method" => "GET",
                            "subpath" => "/api/firewall/port_forwards/config",
                            "getparameter" => array()   );

        $response = ($this->ApiCall($parameter));
        $data = json_decode($response);

        return $data;
    }


    private function Maintain()
    {
        $this->MaintainVariable('Ping', $this->Translate('Ping'), 0, 'TR_Online', 1, true);
        $this->MaintainVariable('Connection', $this->Translate('Connection'), 0, 'TR_Online', 2, true);
        $this->MaintainVariable('IpAddress', $this->Translate('IP Address'), 3, '', 3, true);

        $this->MaintainVariable('DeviceName', $this->Translate('DeviceName'), 3, '', 21, true);
        $this->MaintainVariable('Firmware', $this->Translate('Firmware'), 3, '', 21, true);
        $this->MaintainVariable('Serial', $this->Translate('Serial'), 3, '', 21, true);


        $this->MaintainVariable('Load', $this->Translate('CPU load'), 2, 'TR_Percent', 99, true);
        $this->MaintainVariable('Uptime', $this->Translate('Uptime'), 1, 'TR_Uptime', 100, true);


        $this->MaintainVariable('Provider', '', 3, '', 1, false);
        $this->MaintainVariable('Band', '', 3, '', 1, false);
        $this->MaintainVariable('Signal', '', 1, 'TR_Signal', 1, false);
        $this->MaintainVariable('TxGBytes', '', 2, 'TR_Traffic', 1, false);
        $this->MaintainVariable('RxGBytes', '', 2, 'TR_Traffic', 1, false);
        $this->MaintainVariable('Temperature', '', 1, 'TR_Temperature', 1, false);

        $this->MaintainVariable('FailoverActiveInterface', $this->Translate('Failover Active Interface'), 3, '', 21, $this->ReadPropertyBoolean('ShowFailoverInfomation'));



    }


    public function GetState()
    {
        return $this->GetValue('Connection');
    }

    public function GetVariables()
    {
        $children = IPS_GetChildrenIDs($this->InstanceID);
        $data = [];

        foreach ($children as &$child) {
            $variable = (IPS_GetObject($child));
            if ($variable['ObjectType'] != 2) {
                continue;
            }
            if ($variable['ObjectIdent'] != "") {
                $name = $variable['ObjectIdent'];
            } else {
                $name = $variable['ObjectName'];
            }

            $data[$name] = (GetValue($child));

        }

        return $data;
    }


    private function RegisterVariableProfiles()
    {
        $this->SendDebug(__FUNCTION__, 'RegisterVariableProfiles()', 0);

        if (IPS_VariableProfileExists('TR_Online')) {
            IPS_DeleteVariableProfile("TR_Online");
        }
        if (IPS_VariableProfileExists('TR_Signal')) {
            IPS_DeleteVariableProfile("TR_Signal");
        }
        if (IPS_VariableProfileExists('TR_Traffic')) {
            IPS_DeleteVariableProfile("TR_Traffic");
        }
        if (IPS_VariableProfileExists('TR_Temperature')) {
            IPS_DeleteVariableProfile("TR_Temperature");
        }
        if (IPS_VariableProfileExists('TR_Uptime')) {
            IPS_DeleteVariableProfile("TR_Uptime");
        }
        if (IPS_VariableProfileExists('TR_Percent')) {
            IPS_DeleteVariableProfile("TR_Percent");
        }

        if (!IPS_VariableProfileExists('TR_Online')) {
            IPS_CreateVariableProfile('TR_Online', 0);
            IPS_SetVariableProfileAssociation('TR_Online', 0, $this->Translate('Offline'), 'Warning', 0xFF0000);
            IPS_SetVariableProfileAssociation('TR_Online', 1, $this->Translate('Online'), 'Ok', 0x00FF00);
        }
        if (!IPS_VariableProfileExists('TR_Signal')) {
            IPS_CreateVariableProfile('TR_Signal', 1);
            IPS_SetVariableProfileText("TR_Signal", "", " dBm");
            IPS_SetVariableProfileValues('TR_Signal', -100, 0, 1);
            IPS_SetVariableProfileIcon("TR_Signal", "Intensity");
        }


        if (!IPS_VariableProfileExists('TR_Traffic')) {
            IPS_CreateVariableProfile('TR_Traffic', 2);
            IPS_SetVariableProfileDigits('TR_Traffic', 2);
            IPS_SetVariableProfileText('TR_Traffic', '', ' GB');
            IPS_SetVariableProfileValues('TR_Traffic', 0, 100, 0.01);
        }
        if (!IPS_VariableProfileExists('TR_Temperature')) {
            IPS_CreateVariableProfile('TR_Temperature', 1);
            IPS_SetVariableProfileDigits('TR_Temperature', 1);
            IPS_SetVariableProfileText('TR_Temperature', '', ' °C');
            IPS_SetVariableProfileValues('TR_Temperature', 30, 100, 1);
        }

        if (!IPS_VariableProfileExists('TR_Uptime')) {
            IPS_CreateVariableProfile('TR_Uptime', 1);
            IPS_SetVariableProfileDigits('TR_Uptime', 1);
            IPS_SetVariableProfileText('TR_Uptime', '', ' h');
        }

        if (!IPS_VariableProfileExists('TR_Percent')) {
            IPS_CreateVariableProfile('TR_Percent', 2);
            IPS_SetVariableProfileDigits('TR_Percent', 1);
            IPS_SetVariableProfileText('TR_Percent', '', ' %');
            IPS_SetVariableProfileValues('TR_Percent', 0, 100, 0.1);
        }


    }
}
