### TeltonikaRouter

Mit dieser Instanz können die Parameter eines Routers überwacht werden. 
Außerdem kann z.B. ein Neustart oder Update erfolgen. 

#### Einstellungen der Geräte-Instanz

##### Host 
IP-Adresse oder Hostname des Gerätes.

##### Port 
Port des Webinterfaces

##### Benutzername 
Benutzername des Administrators 

##### Passwort 
Passwort des Administrators

##### Zeitüberschreitung 
Zeitüberschreitung (Timeout) bei regulären Anfragen an das Gerät.
Das Firmwareupdate verwendet ein eigenes Timeout.

##### Update Interval  
Intevall für die Anfragen an das Gerätes


#### Verschlüsselungseinstellungen
##### SSL
Schaltet auf eine verschlüsselte Verbindung (HTTPS) um.

##### Server Überprüfen
Prüft ob das Zertifikat zum Server passt

##### Zertifikat Überprüfen
Prüft die Zertifikatskette (Bei selbstsigniertem Zertifikat deaktivieren)



#### Variablen 

##### Ping 
Zeigt ob das Gerät Online ist.

##### Verbindung 
Zeigt ob eine Verbindung zur Programmierschnittstelle hergestellt werden konnte. 

##### IP-Adresse 
IP-Adresse des Routers (aus der HOST-Einstellung)

##### Firmware
aktuelle Firmwareversion des Routers

##### Gerätename	
Gerätename des Routers 

##### Seriennummer	
Seriennummer des Routers 


##### Modem Provider (Je Modem z.B. "Modem 1 Provider") 
Identifikation des Aktuellen Providers

##### Modem Band (Je Modem z.B. "Modem 1 Band") 
Aktuelles Band der Datenverbindung

##### Modem CCID (Je Modem z.B. "Modem 1 CCID") 
Kartennummer.


##### Modem Signal (RSSI) (Je Modem z.B. "Modem 1 Signal (RSSI)") 
Verbindungsstärke (RSSI) der Mobilfunkverbindung.


##### Modem Send GBytes (Je Modem z.B. "Modem 1 Send GBytes") 
Gesendete Daten in Gigabyte

##### Modem Received GBytes (Je Modem z.B. "Modem 1 Received GBytes") 
Empfangene Daten in Gigabyte


##### Modem Temperatur (Je Modem z.B. "Modem 1 Temperatur") 
Temperatur des Modems 

##### CPU-Last	
Last der CPU in Prozent. (Die Last der Kerne wird addiert. Daher kann bei mehrern Kernen die Last über 100% betragen.)

##### Betriebszeit	
Laufzeit des Routers seit dem letzten Neustart. 




#### Aktualisieren der Varaiblen
```php
TR_UpdateValues(12345);
```

#### Aktualisieren Gerätefirmware über OTAA
```php
TR_FirmwareUpdate(12345);
```
Bei einem Update müssen mehrere Schritte durchlaufen werden. Daher muss der Befehl mehrfach ausgeführt werden. 

#### Gibt den Verbindungsstatus zurück. 
```php
TR_GetState(12345);
```

#### Gibt ein Array der Variablen zurück.
```php
TR_GetVariables(12345);
```

#### Login erzwingen nachdem z.B. das Kennwort geändert wurde.
```php
TR_Login(12345,true /* login erzwingen auch wenn dieser zuvor fehlgeschlagen war */);
```

#### Gibt die gesamte URL zum Webinterface zurück
```php
TR_GetRouterConfigurationPage(12345);
```

#### Eigene Reqests an die Router API senden. 
Beispiel: Port-Forwarding aus dem VPN an die Kamera im Garten

```php
// Daten für Portforwarding zusammenstellen:
$data = array(
        "name"=> "Kamera_Garten", 		// Name für die Portweiterleitung
        "proto"=> array("tcp"),			// Protokoll
        "src_dport"=> "80",				// Externer Port
        "dest_ip"=> "192.168.2.5",		// IP des internen Gerätes
        "dest_port"=> "80",				// Port des Gerätes
        "enabled"=> "1",				// Aktiviere diese Regel 
		"src"=>"openvpn",				// Port-Weiterleitung nur aus dem openVPN erlauben
		"dest"=> "lan",					// Port-Weiterleitung in das LAN erlauben
		"reflection"=> "1",				// NAT reflection bzw. NAT-Loopback
		"priority"=> "10"				// Prorität der Regel 
        );
		
//Daten JSON-Formatieren:	
$postfield = json_encode(array("data" => $data,)); 

// Alle Parameter für einen API-Request zusammen bauen:
$parameter = array( "method"=>"POST",
                    "postfield"=>$postfield,
                    "subpath" => "/api/firewall/port_forwards/config",
                    "getparameter"=> array()
					);

// API-Request ausführen:		
$response = TR_ApiCall(12345, $parameter);

// Antwort in ein Objekt zurückwandeln:
$data = json_decode($response);

// Abfragen ob Request erfolgreich war:
if($data->apidata->success) 
    echo "erfolgreich \r\n";

// Antwort als Echo in schön formatiertem JSON ausgeben:

echo json_encode($data->apidata, JSON_PRETTY_PRINT);	

```

