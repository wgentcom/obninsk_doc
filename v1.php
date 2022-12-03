<?php ?>
<META http-equiv=Content-Type content="text/html; charset=windows-1251">
<TITLE> Obninsk DOC2TEXT converter v 1.0 by Max Brown</TITLE>
��� ������ ���������� �� ���������� ���, ��� ������ � ����� ������ ������ �� "������� ����", ��� � ����� alpha,
� � ������������ � ���������� ���������� ���������� Word.
<?php
require_once("../functions.php"); // just for debug() function
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
//require_once("obninsk_doc1.php");
$filename=$_GET["file"]; if($filename=="") if($filename=="") $filename="readme.doc"; 
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
analyse($hex);  /////////////////////////////////////////// ����� �������� �������
exit;

function analyse($hex){
global $sectorsize;
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
 ?><tr><td colspan=9 style="border:1px #ff0000 solid"><? 
// echo $s;
 ?><hr><? 
	if( bin2hex($catTbl[$i]["objname"]) == "57006f007200640044006f00630075006d0065006e0074000000" ) {
 	echo "WordDocument!";
		$txtbegoffset=substr($s, 2*0x18, 2*4);
		$txtendoffset=substr($s, 2*0x1C, 2*4);
		debug("\$txtbegoffset=$txtbegoffset; \$txtendoffset=$txtendoffset;");
		$txtbegoffsint=dword2int($txtbegoffset);
		$txtendoffsint=dword2int($txtendoffset);
		$word6len=dword2int(substr($s, 2*0x34, 2*4));
		$word97len=dword2int(substr($s, 2*0x4C, 2*4));
		debug("\$txtbegoffsint=$txtbegoffsint; \$txtendoffsint=$txtendoffsint; \$word6len=$word6len; \$word97len=$word97len; strlen(\$s)=".strlen($s));
//		$hextxt=substr( $s, 2*($txtbegoffsint+$sectorsize), 2*($txtendgoffsint-$txtbegoffsint+$sectorsize) );
/*
		$hextxt=substr( $s, 2*($txtbegoffsint+$sectorsize), 2*($word97len+512) );
  debughex($hextxt);
		debug("\n<hr>".unidecode($hextxt));
*/
  $hextxt=substr( $s, 2*($txtbegoffsint+$sectorsize));
//		debug("\n<hr>".unidecode($hextxt));
		while ($zeropos=detectZero($hextxt)){
		////////////////////  �����������!!!!  ���� ���� ������� �� ������� �������, � �� � ������� �������.
		 $hexlen=strlen($hextxt);
		 debug("zero at ".$zeropos);
		 $hx1=substr($hextxt, 0, $zeropos);
			if($zeropos+1024>$hexlen) {debug ("over end"); $hx2="";}
			else $hx2=substr($hextxt, $zeropos+1024);
			$hx=substr($hextxt, $zeropos, 1024);
			debughx($hx);
			$hextxt=$hx1.$hx2;
		} //while zero presents
  debughex($hextxt);
		debug("\n".unidecode($hextxt));
	} //if main stream aka WordDocument


// echo pack("H*",$s);
 ?><hr><? 
 $s=unidecode($s);
////////////////////////////////////// echo $s;
 ?></td></tr><? 
/* ?><hr color=green><? */
 ?></tr><? 
 } //for
?></table><?

?>
<hr color="#FF0000">
��� �����, �� ���� �� �������� �� ��������� �� ������ ���������� ������.<br>
� ������ ���������� ������ ����������� (� ����� readme.doc) � ������� ����� 3:
<?
$sector=3;
$s0=readhex($hex, $BBD, $sector);
?><hr color="#FF0000"><?
/////////////////////////// echo unidecode($s0);
?><hr color="#FF0000"><?

}//function analyse($hex)


function unidecode($hex){

$html=true;

$c20=(int)(hexdec("20"));
$c00=(int)(hexdec("00"));
$br=($html)?"<br />":"\r\n";                $br=" ";
$c_AA=(int)hexdec("10");
$c_a=(int)hexdec("30");
$dec_AA=hexdec("10");
$dec_a=hexdec("30");

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
		$txt=$txt.$c;
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

function dword2int($dword){ 
//����������� ����������������� � ����� �� ������� ��������
 if( preg_match("/[^a-f0-9]/si", $dword) ) return 0;
 if(strlen($dword)>8) return -1;
	if($dword=="ffffffff" || $dword=="FFFFFFFF") return -1;
 while(strlen($dword)<8) $dword=$dword."0";
 $hex="";
 for($i=3; $i>=0; $i--){
  $hex=$hex.substr($dword, $i*2, 2);
 } //for
 return hexdec($hex);
} // function dword2int($dword)

function chardword($hex, $offset){
// ���������� 8 �������� � ������� $offset
 $offset=$offset*2; // because 1 character is converted to 2 hexadecimal digits
 if(strlen($hex)+8<$offset) echo "<br>dword over: len=".strlen($hex).", offset=$offset<br>";
 return substr($hex, $offset, 8);
} //function dword($hex, $offset)

function char2($hex, $offset){
// ���������� 2 ������� � ������� $offset
 $offset=$offset*2; // because 1 character is converted to 2 hexadecimal digits
 if(strlen($hex)+2<$offset) echo "<br>char over: len=".strlen($hex).", offset=$offset<br>";
 return substr($hex, $offset, 2);
} //function dword($hex, $offset)

function dword($hex, $offset){
// ���������� ���������� �������� 8 �������� � ������� $offset
 return dword2int( chardword($hex, $offset) ); 
} //function dword($hex, $offset)

function exp2($exp){
 $ret=1;
 for($i=1; $i<=$exp; $i++) $ret=$ret*2;
 return $ret;
}

function debughex($hex){
 $hexlen=strlen($hex);
 for($i=0; $i<$hexlen; $i=$i+4){
	 $hx=substr($hex, $i, 4);
		echo $hx."(".unidecode($hx).") ";
 }
}

function detectZero($hex){
 $hexlen=strlen($hex);
 for($i=0; $i<$hexlen; $i=$i+4){
	 $hx=substr($hex, $i, 4);
		if($hx=="0000") return $i;
 }
	return false; //���� �� ����� 0000
}

function debughx($hx){
 $hxlen=strlen($hx);
 for($i=0; $i<$hxlen; $i=$i+4){
	 $h=substr($hx, $i, 4);
		echo "<br>".$i.":".$h;
 }
}

?>