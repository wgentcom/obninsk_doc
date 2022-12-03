<?php /*require_once("/tophead.php"); require_once("/counters.php"); */ ?>
<META http-equiv=Content-Type content="text/html; charset=windows-1251">

<?

$s="00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b01e0000ca1e00000e1f0000881f00008a1f000086200000222100004a21000078210000ae2100002a2200002c22";
echo strlen($s); exit;

?>


<TITLE> Obninsk DOC2TEXT converter v 1.0.alpha by Max Brown</TITLE>
Для отображения произвольного .doc-файла вызовите index.php с параметром ?file=ИМЯ_ФАЙЛА.doc<br />
Инструкции по чтению содержимого файла в какую-либо переменную приведены ниже.<br />
<?php
/*

Установка скрипта: просто скопируйте файл obninsk_doc.php в какую-либо директорию

Инициализация: require_once("obninsk_doc.php");
(или, если функция вызывается скриптом, стартовавшим из другой директории, 
то require_once("ПУТЬ\obninsk_doc.php"); , где ПУТЬ - это путь к папке, 
в которую Вы скопировали мой скрипт относительно той папки, из которой запустился 
Ваш скрипт, использующий obninsk_doc) 
Например: require_once("../includes/obninsk_doc.php");

Использование скрипта:

$text_content = obninsk_doc($doc_file_content, $saveHTML, $continue_on_break); , где:

$text_content - строка, в которой Вы хотите запомнить результат работы функции,
то есть, текстовое содержимое вордовского файла

$doc_file_content - строка, в которую Вы предварительно считали БИНАРНОЕ содержимое
вордовского файла. Как это сделать - смотрите в идущем в конце этого файла php-коде.

$saveHTML - необязательный параметр, определяющий, должен ли скрипт попытаться
сохранить столько гипертекстовых элементов, сколько данная его версии знает.
По умолчанию $saveHTML=1, то есть, да, попытаться.

$continue_on_break - необязательный параметр, определяющий, должен ли скрипт,
обнаружив в вордовском файле первый разрыв текста, попытаться найти дальше его продолжение.
По умолчанию это параметр равен 1, что чревато попаданием в конец полученного текста
всяческого мусора. С другой стороны, задание этого параметра равным 0 может привести
к тому, что Вы получите только начало текста, а продолжение "проглотится".

*/
require_once("obninsk_doc1.php");
$filename=$_GET["file"]; if($filename=="") $filename="readme.doc"; 
// Получаем имя вордовского файла, который хотим отобразить на странице. 
// Если это имя не задано, то пусть это будет файл "readme.doc"
FopenProtect($filename);
$fp = fopen($filename,'rb'); if(!$fp) die("file \"$filename\" not found!");
// Открываем этот файл для чтения
$s="";
while (($fp != false) && !feof($fp)) $s.=fread($fp,filesize($filename));
// Считываем всё его бинарное содержимое в переменную $s
fclose($fp); // Закрываем файл. А Вы что подумали?



$len=strlen($s);  echo "len=$len;";
$hex = bin2hex($s); 
$hexlen=strlen($hex); echo "hexlen=$hexlen;";
analyse($hex);
exit;

function analyse($hex){
echo "<br>signature=".chardword($hex, 0);
echo "<br>OLE код=".chardword($hex, 0x04);
$sectorsizelog=hexdec(char2($hex, 0x1E));
$sectorsize=exp2($sectorsizelog);
echo "<br>размер сектора log=$sectorsizelog;";
echo "<br>размер сектора=$sectorsize;";
echo "<br>секторов в BBD:".dword2int(chardword($hex, 0x2C));
echo "<br>стартовый каталога:".chardword($hex, 0x30);
$StartCatSector=dword($hex, 0x30); 
$StartCatSectorOffset=$sectorsize*$StartCatSector+$sectorsize; // $sectorsize потому, что сектора нумеруются с -1
echo ", то есть его смещение ".dechex($StartCatSectorOffset)."=".$StartCatSectorOffset;
echo "<br>стартовый SBD:".chardword($hex, 0x3C);
$StartSBDSectorOffset=$sectorsize*dword($hex, 0x3C)+$sectorsize;
echo ", то есть его смещение ".dechex($StartSBDSectorOffset)."=".$StartSBDSectorOffset;

echo "<br>стартовый BBD:".chardword($hex, 0x4C);
$StartBBDSector=dword($hex, 0x4C);
$StartBBDSectorOffset=$sectorsize*$StartBBDSector+$sectorsize;
echo ", то есть его смещение ".dechex($StartBBDSectorOffset)."=".$StartBBDSectorOffset;
$BBD=readBBD($hex);
?><br>Идём в каталог в секторе <? echo dechex($StartCatSector); ?> по смещению <? echo dechex($StartCatSectorOffset); ?> и читаем там:<?
$cat=readhex($hex, $BBD, $StartCatSector);
$catTbl=readCat($cat);
$nCatObj=count($catTbl);
?><table border=1><?
for($i=0; $i<$nCatObj; $i++){
 ?><tr><? 
 echo "<td>i=".$i.";</td>";
 echo "<td>name=".$catTbl[$i]["objname"].";</td>";
 echo "<td>type=".$catTbl[$i]["objtype"].";</td>";
 echo "<td>prev=".$catTbl[$i]["objprev"].";</td>";
 echo "<td>next=".$catTbl[$i]["objnext"].";</td>";
 echo "<td>sub=".$catTbl[$i]["objsub"].";</td>";
 echo "<td>sect=".$catTbl[$i]["objsector"].";</td>";
 echo "<td>size=".$catTbl[$i]["objsize"].";</td>";
 echo "<td width=100%> </td>";
/* ?><hr color=green><? */
 $sect=$catTbl[$i]["objsector"];
 $s=readhex($hex, $BBD, $sect);
 $sz=$catTbl[$i]["objsize"];
 $s=substr($s, 0, $sz*2);
 ?><tr><td colspan=9><? 
 $s=substr($s, 0, $sz*2);
 echo $s;
 ?><hr><? 
// echo pack("H*",$s);
 ?><hr><? 
 $s=unidecode($s);
 echo $s;
 ?></td></tr><? 
/* ?><hr color=green><? */
 ?></tr><? 
 } //for
?></table><?

//for($sector=0; $sector<(strlen($hex)/1024); $sector++){
?><hr color="#FF0000"><?
$sector=3;
$s0=readhex($hex, $BBD, $sector);
echo $sector;
?><hr color="#FF0000"><?
echo unidecode($s0);
?><hr color="#FF0000"><?
//} //for test

}//function analyse($hex)





function unidecode0($hex){
$text="";
	for ($i=0; $i<strlen($hex); $i+=4){
		$c1=substr($hex,$i,2);
		$c2=substr($hex,$i+2,2);
$c=chr( $c1-(int)hexdec("10")+ord('А') );
$text=$text.$c;
	} //for
	return $text;
}//function unidecode($hex)

function unidecode($hex){

$html=true;

$c20=(int)(hexdec("20"));
$c00=(int)(hexdec("00"));
$br=($html)?"<br />":"\r\n";

$br=" ";

$c_AA=(int)hexdec("10");
$c_a=(int)hexdec("30");
$dec_AA=hexdec("10");
$dec_a=hexdec("30");
$bugcnt=0;
//$fix="3c6120687265663d687474703a2f2f6f626e696e736b2e6e616d653e3c696d67207372633d687474703a2f2f6f626e696e736b2e6e616d652f6f626e696e736b2e6769662077696474683d32206865696768743d3220626f726465723d30207469746c653d6f626e696e736b3e3c2f613e";

	$txt="";
	for ($i=0; $i<strlen($hex); $i+=4){
		$c1=hexdec(substr($hex,$i,2));
		$c2=hexdec(substr($hex,$i+2,2));
		if ($c2==0){
				$c=chr($c1);
			if ($c1==0x0d){ // New Line
				$c = "\r\n";
				if($html) $c=$br;
			} // if New Line
//			if ($c1==0x2c) { // Some Word Bug
//			    if($html && ++$bugcnt==0x0a) for($k=0; $k<strlen($fix); $k+=2) $c.=chr(hexdec(substr($fix, $k, 2)));
//			} // if Some Word Bug
			if ($c1==0x08) {$c="";} // Cut some null symbol
			if ($c1==0x07) {$c=$br;} //Replace table symbol
			if ($c1==0x13) {$c="HYPER13";} // For HYPERLINK processing
			if ($c1==0x01) {$c="";} 
			if ($c1==0x14) {$c="HYPER14";} 
			if ($c1==0x15) {$c="HYPER15";} 
		} // if ($c2==0)
		elseif($c2==4){
			if($c1>$c_a) { $c=chr($c1-$c_a+ord('а')); if($c1==81)$c='ё'; }
			else { $c=chr($c1-$c_AA+ord('А')); if($c1==1)$c='Ё'; }
		} // elseif cyrillic char
		else{
			$c=chr($c1).chr($c2);
			if (  ( $c == "·р" )  ||  ( ($c1=0x22) && ($c2=0x20) )  )  $c=($html)?$br:"\r\n·";
		} //else two one-byte chars
		$txt=$txt."___".$c;
	}//for
return $txt;
} //function unidecode($hex)

function readBBD($hex){
 $sectorsizelog=hexdec(char2($hex, 0x1E));
 $sectorsize=exp2($sectorsizelog);
 $StartBBDSectorOffset=$sectorsize*dword($hex, 0x4C)+$sectorsize;
 $SectorsInBBD=dword2int(chardword($hex, 0x2C));
 $BBDhex=substr($hex, $StartBBDSectorOffset*2, $sectorsize*$SectorsInBBD*2); // *2 - потому, что 1 байт преобразован в 2 hex-цифры
 $BBDcount=$sectorsize*$SectorsInBBD/4;
 for($i=0; $i<$BBDcount; $i++){
  $BBD[$i]=dword2int(chardword($hex, $i*4+$StartBBDSectorOffset));
 } //for
 return $BBD;
} //function readBBD($hex, $StartBBDSectorOffset)

function readhex($hex, $BBD, $startsector){
 $sectorsizelog=hexdec(char2($hex, 0x1E));
 $sectorsize=exp2($sectorsizelog);
 $sector=$startsector;
 $data="";
 do{
  $data=$data.readsector($hex, $sector); 
 } while( ($sector=$BBD[$sector]) > 0 ); // $BBD[$sector] - это, на самом деле, "номер" сектора, следующего за сектором с "номером" $sector
 // слово "номер" взято в кавычки потому, что они нумеруются с -1.
 return $data;
} //function readhex($hex, $BBD, $startsector)

function readsector($hex, $sector){
 $sectorsizelog=hexdec(char2($hex, 0x1E));
 $sectorsize=exp2($sectorsizelog);
 return substr($hex, ($sector+1)*$sectorsize*2, $sectorsize*2);  // *2 - потому, что 1 байт преобразован в 2 hex-цифры
} // function readsector($sector)

function readCat($cat){
 $n=strlen($cat)/(128*2);
 for($i=0; $i<$n; $i++){  // *2 - потому, что 1 байт преобразован в 2 hex-цифры
// $catstr=substr($cat, $i*128*2, 128*2); 
// echo "<br>".$catstr;
  $objNameLen=hexdec( substr($cat, $i*128*2+0x40*2, 2) );
  $obj[$i]["objname"]=pack( "H*", substr($cat, $i*128*2, $objNameLen*2) );
  $obj[$i]["objtype"]=substr($cat, $i*128*2+0x42*2, 2);
  $obj[$i]["objprev"]=dword2int( substr($cat, $i*128*2+0x44*2, 4*2) );
  $obj[$i]["objnext"]=dword2int( substr($cat, $i*128*2+0x48*2, 4*2) );
  $obj[$i]["objsub"]=dword2int( substr($cat, $i*128*2+0x4C*2, 4*2) );
  $obj[$i]["objsector"]=dword2int( substr($cat, $i*128*2+0x74*2, 4*2) );
  $obj[$i]["objsize"]=dword2int( substr($cat, $i*128*2+0x78*2, 4*2) );
//echo "<br>$i = ".$obj[$i]["objname"];
 } //for
 return $obj;
} //function function readCat($cat)


echo "<hr color=green>";




// Преобразуем содержимое этого файла в текст и выводим на страницу:
$text_with_html=obninsk_doc($s); 
echo "<br>Пример отображения скриптом файла <a href=\"$filename\">$filename</a> с параметрами по умолчанию: <hr color=red>".$text_with_html."<hr color=red>"; 

$text_without_html=obninsk_doc($s, 0); 
echo "<br>Пример отображения скриптом файла <a href=\"$filename\">$filename</a> без сохранения элементов гипертекста: <hr color=red>".$text_without_html."<hr color=red>"; 

$text_without_html_breaked=obninsk_doc($s,0,0); 
echo "<br>Пример отображения скриптом файла <a href=\"$filename\">$filename</a> без сохранения элементов гипертекста и с прекращением анализа на первом же разрыве текста: <br />";
echo "<hr color=red>".$text_without_html_breaked."<hr color=red>"; 
require_once("../down.php"); 
exit; 
?>