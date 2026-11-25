param(
  [Parameter(Mandatory = $true)][string]$Path,
  [Parameter(Mandatory = $true)][string]$OutFile,
  [int]$MaxDimension = 2048
)

# Downscale an image so its long edge fits MaxDimension, then re-encode as JPEG.
#
# Scaling happens through BitmapTransform on the decoder, so the full-size
# raster is never materialized. Re-encoding to JPEG also drops any metadata the
# source carried.
#
# Output header: 8 bytes little-endian (int32 width, int32 height) followed by
# the JPEG bytes, so the caller learns the result size in one read.

$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Runtime.WindowsRuntime

$asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
  $_.Name -eq 'AsTask' -and
  $_.GetParameters().Count -eq 1 -and
  $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'
})[0]

$asTaskAction = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
  $_.Name -eq 'AsTask' -and
  $_.GetParameters().Count -eq 1 -and
  $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncAction'
})[0]

function Await($WinRtTask, $ResultType) {
  $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)
  $netTask = $asTask.Invoke($null, @($WinRtTask))
  $netTask.Wait(-1) | Out-Null
  $netTask.Result
}

function AwaitAction($WinRtAction) {
  $netTask = $asTaskAction.Invoke($null, @($WinRtAction))
  $netTask.Wait(-1) | Out-Null
}

[Windows.Graphics.Imaging.BitmapDecoder, Windows.Graphics.Imaging, ContentType = WindowsRuntime] | Out-Null
[Windows.Graphics.Imaging.BitmapEncoder, Windows.Graphics.Imaging, ContentType = WindowsRuntime] | Out-Null
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
$outWidth = 0
$outHeight = 0
$outBitmap = $null
try {
  $ras = [System.IO.WindowsRuntimeStreamExtensions]::AsRandomAccessStream($inStream)
  $decoder = Await ([Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($ras)) ([Windows.Graphics.Imaging.BitmapDecoder])

  $srcWidth = $decoder.PixelWidth
  $srcHeight = $decoder.PixelHeight
  $longEdge = [Math]::Max($srcWidth, $srcHeight)
  $scale = 1.0
  if ($longEdge -gt $MaxDimension) { $scale = $MaxDimension / $longEdge }

  $outWidth = [Math]::Max(1, [int][Math]::Round($srcWidth * $scale))
  $outHeight = [Math]::Max(1, [int][Math]::Round($srcHeight * $scale))

  $transform = [Windows.Graphics.Imaging.BitmapTransform]::new()
  $transform.ScaledWidth = [uint32]$outWidth
  $transform.ScaledHeight = [uint32]$outHeight
  $transform.InterpolationMode = [Windows.Graphics.Imaging.BitmapInterpolationMode]::Fant

  $outBitmap = Await ($decoder.GetSoftwareBitmapAsync(
    [Windows.Graphics.Imaging.BitmapPixelFormat]::Bgra8,
    [Windows.Graphics.Imaging.BitmapAlphaMode]::Premultiplied,
    $transform,
    [Windows.Graphics.Imaging.ExifOrientationMode]::RespectExifOrientation,
    [Windows.Graphics.Imaging.ColorManagementMode]::DoNotColorManage
  )) ([Windows.Graphics.Imaging.SoftwareBitmap])
} finally {
  $inStream.Dispose()
}

$encoded = [System.IO.MemoryStream]::new()
$outRas = [System.IO.WindowsRuntimeStreamExtensions]::AsRandomAccessStream($encoded)
$encoder = Await ([Windows.Graphics.Imaging.BitmapEncoder]::CreateAsync(
  [Windows.Graphics.Imaging.BitmapEncoder]::JpegEncoderId,
  $outRas
)) ([Windows.Graphics.Imaging.BitmapEncoder])
$encoder.SetSoftwareBitmap($outBitmap)
$encoder.IsThumbnailGenerated = $false
# No metadata is copied: the encoder starts from an empty property set, so the
# JPEG carries no EXIF, GPS, or camera fields from the source.
AwaitAction ($encoder.FlushAsync())

$jpeg = $encoded.ToArray()
$encoded.Dispose()

$file = [System.IO.File]::Create($OutFile)
try {
  $writer = [System.IO.BinaryWriter]::new($file)
  $writer.Write([int32]$outWidth)
  $writer.Write([int32]$outHeight)
  $writer.Write($jpeg)
  $writer.Flush()
} finally {
  $file.Dispose()
}

exit 0
