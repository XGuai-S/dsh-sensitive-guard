param(
  [Parameter(Mandatory = $true)][string]$Path,
  [Parameter(Mandatory = $true)][string]$OutFile,
  [Parameter(Mandatory = $true)][string]$Boxes,
  [string]$Color = '#000000'
)

# Opaque redaction of image regions.
#
# Irreversibility comes from three things, and all three are required:
#
#   1. An opaque fill over the rectangle. No layer, alpha, or blend keeps the
#      original pixels reachable behind it.
#   2. A full re-encode from the modified raster, so no source scanline of the
#      covered region survives in the output file.
#   3. Empty metadata on save, so EXIF/GPS/camera fields are not carried over.
#
# `-Boxes` is a `;`-separated list of `x,y,w,h` in image pixels.

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

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

# FlushAsync returns IAsyncAction, not IAsyncOperation<T>, so it needs the
# non-generic AsTask overload.
$asTaskAction = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
  $_.Name -eq 'AsTask' -and
  $_.GetParameters().Count -eq 1 -and
  $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncAction'
})[0]

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

# Decode to BGRA8 so every source format shares one writable pixel layout.
$inStream = [System.IO.MemoryStream]::new($bytes)
$bitmap = $null
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
$stride = $width * 4
$pixelBytes = New-Object byte[] ($stride * $height)
$bitmap.CopyToBuffer([System.Runtime.InteropServices.WindowsRuntime.WindowsRuntimeBufferExtensions]::AsBuffer($pixelBytes))

# Parse "#RRGGBB".
if ($Color -notmatch '^#?([0-9A-Fa-f]{6})$') {
  [Console]::Error.Write('BAD_COLOR')
  exit 6
}
$hex = $Matches[1]
$r = [Convert]::ToByte($hex.Substring(0, 2), 16)
$g = [Convert]::ToByte($hex.Substring(2, 2), 16)
$b = [Convert]::ToByte($hex.Substring(4, 2), 16)

foreach ($entry in ($Boxes -split ';')) {
  if ([string]::IsNullOrWhiteSpace($entry)) { continue }
  $parts = $entry -split ','
  if ($parts.Count -ne 4) { continue }
  $bx = [int]$parts[0]
  $by = [int]$parts[1]
  $bw = [int]$parts[2]
  $bh = [int]$parts[3]
  if ($bw -le 0 -or $bh -le 0) { continue }

  $x0 = [Math]::Max(0, $bx)
  $y0 = [Math]::Max(0, $by)
  $x1 = [Math]::Min($width, $bx + $bw)
  $y1 = [Math]::Min($height, $by + $bh)

  for ($y = $y0; $y -lt $y1; $y++) {
    $rowStart = $y * $stride
    for ($x = $x0; $x -lt $x1; $x++) {
      $i = $rowStart + ($x * 4)
      # BGRA order, alpha forced opaque.
      $pixelBytes[$i] = $b
      $pixelBytes[$i + 1] = $g
      $pixelBytes[$i + 2] = $r
      $pixelBytes[$i + 3] = 255
    }
  }
}

# Write the modified pixels back and encode a fresh file.
$outBitmap = [Windows.Graphics.Imaging.SoftwareBitmap]::CreateCopyFromBuffer(
  [System.Runtime.InteropServices.WindowsRuntime.WindowsRuntimeBufferExtensions]::AsBuffer($pixelBytes),
  [Windows.Graphics.Imaging.BitmapPixelFormat]::Bgra8,
  $width,
  $height,
  [Windows.Graphics.Imaging.BitmapAlphaMode]::Premultiplied
)

$outStream = [System.IO.MemoryStream]::new()
$outRas = [System.IO.WindowsRuntimeStreamExtensions]::AsRandomAccessStream($outStream)
$encoder = Await ([Windows.Graphics.Imaging.BitmapEncoder]::CreateAsync(
  [Windows.Graphics.Imaging.BitmapEncoder]::PngEncoderId,
  $outRas
)) ([Windows.Graphics.Imaging.BitmapEncoder])
$encoder.SetSoftwareBitmap($outBitmap)
# No thumbnail, and no metadata is ever written: the encoder starts from an
# empty property set, so no EXIF/GPS/camera field is carried over from the
# source. The covered region is gone from the raster, so no scanline of it can
# be recovered from the output either.
$encoder.IsThumbnailGenerated = $false
AwaitAction ($encoder.FlushAsync())

# FlushAsync has already pushed the encoded bytes into the adapter's stream, so
# no extra flush is needed; the adapter exposes none.
[System.IO.File]::WriteAllBytes($OutFile, $outStream.ToArray())
$outStream.Dispose()

exit 0
