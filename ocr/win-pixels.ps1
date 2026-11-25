param(
  [Parameter(Mandatory = $true)][string]$Path,
  [Parameter(Mandatory = $true)][string]$OutFile
)

# Dump decoded pixels for in-process QR decoding.
#
# File layout: an 8-byte little-endian header (int32 width, int32 height)
# followed by width*height*4 bytes of BGRA. Decoding here rather than in the
# caller means every format the platform can read (PNG/JPEG/WebP/GIF/BMP) is
# supported without a JavaScript image decoder.

$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Runtime.WindowsRuntime

$asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
  $_.Name -eq 'AsTask' -and
  $_.GetParameters().Count -eq 1 -and
  $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'
})[0]

function Await($WinRtTask, $ResultType) {
  $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)
  $netTask = $asTask.Invoke($null, @($WinRtTask))
  $netTask.Wait(-1) | Out-Null
  $netTask.Result
}

[Windows.Graphics.Imaging.BitmapDecoder, Windows.Graphics.Imaging, ContentType = WindowsRuntime] | Out-Null
[Windows.Storage.Streams.RandomAccessStreamReference, Windows.Storage.Streams, ContentType = WindowsRuntime] | Out-Null

if (-not (Test-Path -LiteralPath $Path)) {
  [Console]::Error.Write('MISSING_IMAGE')
  exit 4
}

$bytes = [System.IO.File]::ReadAllBytes($Path)
if ($bytes.Length -eq 0) {
  [Console]::Error.Write('EMPTY_IMAGE')
  exit 5
}

$inStream = [System.IO.MemoryStream]::new($bytes)
try {
  $ras = [System.IO.WindowsRuntimeStreamExtensions]::AsRandomAccessStream($inStream)
  $decoder = Await ([Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($ras)) ([Windows.Graphics.Imaging.BitmapDecoder])
  $bitmap = Await ($decoder.GetSoftwareBitmapAsync(
    [Windows.Graphics.Imaging.BitmapPixelFormat]::Bgra8,
    [Windows.Graphics.Imaging.BitmapAlphaMode]::Premultiplied
  )) ([Windows.Graphics.Imaging.SoftwareBitmap])
} finally {
  $inStream.Dispose()
}

$width = $bitmap.PixelWidth
$height = $bitmap.PixelHeight
$pixelBytes = New-Object byte[] ($width * 4 * $height)
$bitmap.CopyToBuffer([System.Runtime.InteropServices.WindowsRuntime.WindowsRuntimeBufferExtensions]::AsBuffer($pixelBytes))

$out = [System.IO.File]::Create($OutFile)
try {
  $writer = [System.IO.BinaryWriter]::new($out)
  $writer.Write([int32]$width)
  $writer.Write([int32]$height)
  $writer.Write($pixelBytes)
  $writer.Flush()
} finally {
  $out.Dispose()
}

exit 0
