<?php
session_start();

// 혼동되는 문자 제외 (0/O, 1/I/l)
$chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
$code  = '';
for ( $i = 0; $i < 5; $i++ ) {
    $code .= $chars[ random_int( 0, strlen( $chars ) - 1 ) ];
}
$_SESSION['captcha_code'] = $code;

$width  = 150;
$height = 50;

// 1단계: 임시 이미지에 텍스트 그리기 (내장 폰트 사용)
$tmp = imagecreatetruecolor( $width, $height );
$bg  = imagecolorallocate( $tmp, 255, 255, 255 );
imagefill( $tmp, 0, 0, $bg );

for ( $i = 0; $i < strlen( $code ); $i++ ) {
    $c = imagecolorallocate( $tmp, rand(20,100), rand(20,100), rand(20,100) );
    $x = 12 + $i * 27;
    $y = rand(8, 22);
    imagestring( $tmp, 5, $x, $y, $code[$i], $c );
}

// 2단계: 파형 왜곡 적용
$final = imagecreatetruecolor( $width, $height );
$bg2   = imagecolorallocate( $final, 240, 240, 240 );
imagefill( $final, 0, 0, $bg2 );

for ( $x = 0; $x < $width; $x++ ) {
    for ( $y = 0; $y < $height; $y++ ) {
        $sx = (int)( $x + sin( $y / 8.0 ) * 5 );
        $sy = (int)( $y + sin( $x / 12.0 ) * 4 );
        if ( $sx >= 0 && $sx < $width && $sy >= 0 && $sy < $height ) {
            imagesetpixel( $final, $x, $y, imagecolorat( $tmp, $sx, $sy ) );
        }
    }
}
imagedestroy( $tmp );

// 3단계: 노이즈
for ( $i = 0; $i < 200; $i++ ) {
    $c = imagecolorallocate( $final, rand(150,220), rand(150,220), rand(150,220) );
    imagesetpixel( $final, rand(0,$width-1), rand(0,$height-1), $c );
}
for ( $i = 0; $i < 5; $i++ ) {
    $c = imagecolorallocate( $final, rand(150,210), rand(150,210), rand(150,210) );
    imageline( $final, rand(0,$width/2), rand(0,$height), rand($width/2,$width), rand(0,$height), $c );
}

header( 'Content-Type: image/png' );
header( 'Cache-Control: no-cache, no-store, must-revalidate' );
imagepng( $final );
imagedestroy( $final );
?>
