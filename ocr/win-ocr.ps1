param(
  [Parameter(Mandatory = $true)][string]$Path,
  [string]$Language = 'zh-Hans-CN',
  [Parameter(Mandatory = $true)][string]$OutFile
)

# Windows.Media.Ocr runner with bounding boxes.
#
# Output: one line per recognized text line,
#   "<index>\t<x>\t<y>\t<w>\t<h>\t<text>"
# The rectangle is the union of the line's word boxes, in image pixels.
#
# The Chinese recognizer reports 0.000 confidence for every word, so no
# confidence value is emitted; callers judge reliability by text shape.

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

[Windows.Media.Ocr.OcrEngine, Windows.Foundation, ContentType = WindowsRuntime] | Out-Null
[Windows.Graphics.Imaging.BitmapDecoder, Windows.Graphics.Imaging, ContentType = WindowsRuntime] | Out-Null
[Windows.Globalization.Language, Windows.Globalization, ContentType = WindowsRuntime] | Out-Null
[Windows.Storage.Streams.RandomAccessStreamReference, Windows.Storage.Streams, ContentType = WindowsRuntime] | Out-Null

if (-not (Test-Path -LiteralPath $Path)) {
  [Console]::Error.Write('MISSING_IMAGE')
  exit 4
}

$engine = $null
if ($Language) {
  try {
    $lang = [Windows.Globalization.Language]::new($Language)
    $engine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromLanguage($lang)
  } catch {
    $engine = $null
  }
}
if ($null -eq $engine) {
  $engine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromUserProfileLanguages()
}
if ($null -eq $engine) {
  [Console]::Error.Write('NO_ENGINE')
  exit 3
}

$bytes = [System.IO.File]::ReadAllBytes($Path)
if ($bytes.Length -eq 0) {
  [Console]::Error.Write('EMPTY_IMAGE')
  exit 5
}

$stream = [System.IO.MemoryStream]::new($bytes)
try {
  $ras = [System.IO.WindowsRuntimeStreamExtensions]::AsRandomAccessStream($stream)
  $decoder = Await ([Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($ras)) ([Windows.Graphics.Imaging.BitmapDecoder])
  $bitmap = Await ($decoder.GetSoftwareBitmapAsync()) ([Windows.Graphics.Imaging.SoftwareBitmap])
  $result = Await ($engine.RecognizeAsync($bitmap)) ([Windows.Media.Ocr.OcrResult])
} finally {
  $stream.Dispose()
}

$index = 0
$output = [System.Text.StringBuilder]::new()
foreach ($line in $result.Lines) {
  $text = $line.Text
  if ([string]::IsNullOrWhiteSpace($text)) { continue }

  $minX = [double]::MaxValue
  $minY = [double]::MaxValue
  $maxX = 0.0
  $maxY = 0.0
  $count = 0
  foreach ($word in $line.Words) {
    $rect = $word.BoundingRect
    if ($rect.Width -le 0 -or $rect.Height -le 0) { continue }
    if ($rect.X -lt $minX) { $minX = $rect.X }
    if ($rect.Y -lt $minY) { $minY = $rect.Y }
    $right = $rect.X + $rect.Width
    $bottom = $rect.Y + $rect.Height
    if ($right -gt $maxX) { $maxX = $right }
    if ($bottom -gt $maxY) { $maxY = $bottom }
    $count += 1
  }
  if ($count -eq 0) { continue }

  $index += 1
  $w = $maxX - $minX
  $h = $maxY - $minY
  $null = $output.AppendLine(("{0}`t{1:F0}`t{2:F0}`t{3:F0}`t{4:F0}`t{5}" -f $index, $minX, $minY, $w, $h, $text))
}

[System.IO.File]::WriteAllText($OutFile, $output.ToString(), [System.Text.UTF8Encoding]::new($false))

exit 0
