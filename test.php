<?php /*require_once("/tophead.php"); require_once("/counters.php"); */ ?>
<META http-equiv=Content-Type content="text/html; charset=windows-1251">

<?

$s="00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b01e0000ca1e00000e1f0000881f00008a1f000086200000222100004a21000078210000ae2100002a2200002c22";
echo strlen($s); exit;

?>


<TITLE> Obninsk DOC2TEXT converter v 1.0.alpha by Max Brown</TITLE>
��� ����������� ������������� .doc-����� �������� index.php � ���������� ?file=���_�����.doc<br />
���������� �� ������ ����������� ����� � �����-���� ���������� ��������� ����.<br />
<?php
/*

��������� �������: ������ ���������� ���� obninsk_doc.php � �����-���� ����������

�������������: require_once("obninsk_doc.php");
(���, ���� ������� ���������� ��������, ������������ �� ������ ����������, 
�� require_once("����\obninsk_doc.php"); , ��� ���� - ��� ���� � �����, 
� ������� �� ����������� ��� ������ ������������ ��� �����, �� ������� ���������� 
��� ������, ������������ obninsk_doc) 
��������: require_once("../includes/obninsk_doc.php");

������������� �������:

$text_content = obninsk_doc($doc_file_content, $saveHTML, $continue_on_break); , ���:

$text_content - ������, � ������� �� ������ ��������� ��������� ������ �������,
�� ����, ��������� ���������� ����������� �����

$doc_file_content - ������, � ������� �� �������������� ������� �������� ����������
����������� �����. ��� ��� ������� - �������� � ������ � ����� ����� ����� php-����.

$saveHTML - �������������� ��������, ������������, ������ �� ������ ����������
��������� ������� �������������� ���������, ������� ������ ��� ������ �����.
�� ��������� $saveHTML=1, �� ����, ��, ����������.

$continue_on_break - �������������� ��������, ������������, ������ �� ������,
��������� � ���������� ����� ������ ������ ������, ���������� ����� ������ ��� �����������.
�� ��������� ��� �������� ����� 1, ��� ������� ���������� � ����� ����������� ������
���������� ������. � ������ �������, ������� ����� ��������� ������ 0 ����� ��������
� ����, ��� �� �������� ������ ������ ������, � ����������� "�����������".

*/
require_once("obninsk_doc1.php");
$filename=$_GET["file"]; if($filename=="") $filename="readme.doc"; 
// �������� ��� ����������� �����, ������� ����� ���������� �� ��������. 
// ���� ��� ��� �� ������, �� ����� ��� ����� ���� "readme.doc"
FopenProtect($filename);
$fp = fopen($filename,'rb'); if(!$fp) die("file \"$filename\" not found!");
// ��������� ���� ���� ��� ������
$s="";
while (($fp != false) && !feof($fp)) $s.=fread($fp,filesize($filename));
// ��������� �� ��� �������� ���������� � ���������� $s
fclose($fp); // ��������� ����. � �� ��� ��������?



$len=strlen($s);  echo "len=$len;";
$hex = bin2hex($s); 
$hexlen=strlen($hex); echo "hexlen=$hexlen;";
analyse($hex);
exit;

function analyse($hex){
echo "<br>signature=".chardword($hex, 0);
echo "<br>OLE ���=".chardword($hex, 0x04);
$sectorsizelog=hexdec(char2($hex, 0x1E));
$sectorsize=exp2($sectorsizelog);
echo "<br>������ ������� log=$sectorsizelog;";
echo "<br>������ �������=$sectorsize;";
echo "<br>�������� � BBD:".dword2int(chardword($hex, 0x2C));
echo "<br>��������� ��������:".chardword($hex, 0x30);
$StartCatSector=dword($hex, 0x30); 
$StartCatSectorOffset=$sectorsize*$StartCatSector+$sectorsize; // $sectorsize ������, ��� ������� ���������� � -1
echo ", �� ���� ��� �������� ".dechex($StartCatSectorOffset)."=".$StartCatSectorOffset;
echo "<br>��������� SBD:".chardword($hex, 0x3C);
$StartSBDSectorOffset=$sectorsize*dword($hex, 0x3C)+$sectorsize;
echo ", �� ���� ��� �������� ".dechex($StartSBDSectorOffset)."=".$StartSBDSectorOffset;

echo "<br>��������� BBD:".chardword($hex, 0x4C);
$StartBBDSector=dword($hex, 0x4C);
$StartBBDSectorOffset=$sectorsize*$StartBBDSector+$sectorsize;
echo ", �� ���� ��� �������� ".dechex($StartBBDSectorOffset)."=".$StartBBDSectorOffset;
$BBD=readBBD($hex);
?><br>��� � ������� � ������� <? echo dechex($StartCatSector); ?> �� �������� <? echo dechex($StartCatSectorOffset); ?> � ������ ���:<?
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
$c=chr( $c1-(int)hexdec("10")+ord('�') );
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
			if($c1>$c_a) { $c=chr($c1-$c_a+ord('�')); if($c1==81)$c='�'; }
			else { $c=chr($c1-$c_AA+ord('�')); if($c1==1)$c='�'; }
		} // elseif cyrillic char
		else{
			$c=chr($c1).chr($c2);
			if (  ( $c == "��" )  ||  ( ($c1=0x22) && ($c2=0x20) )  )  $c=($html)?$br:"\r\n�";
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
 $BBDhex=substr($hex, $StartBBDSectorOffset*2, $sectorsize*$SectorsInBBD*2); // *2 - ������, ��� 1 ���� ������������ � 2 hex-�����
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
 } while( ($sector=$BBD[$sector]) > 0 ); // $BBD[$sector] - ���, �� ����� ����, "�����" �������, ���������� �� �������� � "�������" $sector
 // ����� "�����" ����� � ������� ������, ��� ��� ���������� � -1.
 return $data;
} //function readhex($hex, $BBD, $startsector)

function readsector($hex, $sector){
 $sectorsizelog=hexdec(char2($hex, 0x1E));
 $sectorsize=exp2($sectorsizelog);
 return substr($hex, ($sector+1)*$sectorsize*2, $sectorsize*2);  // *2 - ������, ��� 1 ���� ������������ � 2 hex-�����
} // function readsector($sector)

function readCat($cat){
 $n=strlen($cat)/(128*2);
 for($i=0; $i<$n; $i++){  // *2 - ������, ��� 1 ���� ������������ � 2 hex-�����
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




// ����������� ���������� ����� ����� � ����� � ������� �� ��������:
$text_with_html=obninsk_doc($s); 
echo "<br>������ ����������� �������� ����� <a href=\"$filename\">$filename</a> � ����������� �� ���������: <hr color=red>".$text_with_html."<hr color=red>"; 

$text_without_html=obninsk_doc($s, 0); 
echo "<br>������ ����������� �������� ����� <a href=\"$filename\">$filename</a> ��� ���������� ��������� �����������: <hr color=red>".$text_without_html."<hr color=red>"; 

$text_without_html_breaked=obninsk_doc($s,0,0); 
echo "<br>������ ����������� �������� ����� <a href=\"$filename\">$filename</a> ��� ���������� ��������� ����������� � � ������������ ������� �� ������ �� ������� ������: <br />";
echo "<hr color=red>".$text_without_html_breaked."<hr color=red>"; 
require_once("../down.php"); 
exit; 
?>