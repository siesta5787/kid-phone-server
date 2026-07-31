# One-off PWA icon generator - no Python/ImageMagick available on this
# machine, so this uses .NET's built-in System.Drawing instead. Draws a
# simple rounded-square brand-blue background with a white phone glyph.
# Re-run manually if the icons ever need to change; not part of the build.
Add-Type -AssemblyName System.Drawing

function New-Icon {
    param(
        [int]$Size,
        [string]$OutPath,
        [bool]$Maskable
    )

    $bmp = New-Object System.Drawing.Bitmap $Size, $Size
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias

    $bg = [System.Drawing.Color]::FromArgb(255, 0x25, 0x63, 0xeb)
    $bgBrush = New-Object System.Drawing.SolidBrush $bg

    if ($Maskable) {
        # Maskable icons get cropped to arbitrary shapes (circle, squircle,
        # etc.) by the OS - fill edge-to-edge and keep the glyph inside the
        # inner ~80% safe zone instead of using a rounded-rect inset.
        $g.FillRectangle($bgBrush, 0, 0, $Size, $Size)
        $margin = [int]($Size * 0.22)
    } else {
        $radius = [int]($Size * 0.2)
        $path = New-Object System.Drawing.Drawing2D.GraphicsPath
        $d = $radius * 2
        $path.AddArc(0, 0, $d, $d, 180, 90)
        $path.AddArc($Size - $d, 0, $d, $d, 270, 90)
        $path.AddArc($Size - $d, $Size - $d, $d, $d, 0, 90)
        $path.AddArc(0, $Size - $d, $d, $d, 90, 90)
        $path.CloseFigure()
        $g.FillPath($bgBrush, $path)
        $margin = [int]($Size * 0.15)
    }

    # Simple phone glyph: rounded-rect body + a small "home" line near the
    # bottom, both in white, centered within the safe zone.
    $white = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::White)
    $phoneW = $Size - ($margin * 2)
    $phoneH = [int]($phoneW * 1.7)
    if ($phoneH -gt ($Size - ($margin * 2))) {
        $phoneH = $Size - ($margin * 2)
        $phoneW = [int]($phoneH / 1.7)
    }
    $px = [int](($Size - $phoneW) / 2)
    $py = [int](($Size - $phoneH) / 2)
    $phoneRadius = [int]($phoneW * 0.22)

    $phonePath = New-Object System.Drawing.Drawing2D.GraphicsPath
    $pd = $phoneRadius * 2
    $phonePath.AddArc($px, $py, $pd, $pd, 180, 90)
    $phonePath.AddArc($px + $phoneW - $pd, $py, $pd, $pd, 270, 90)
    $phonePath.AddArc($px + $phoneW - $pd, $py + $phoneH - $pd, $pd, $pd, 0, 90)
    $phonePath.AddArc($px, $py + $phoneH - $pd, $pd, $pd, 90, 90)
    $phonePath.CloseFigure()
    $g.FillPath($white, $phonePath)

    # "Screen" cutout in brand blue so the glyph doesn't read as a solid
    # blob at small sizes.
    $screenMargin = [int]($phoneW * 0.14)
    $screenW = $phoneW - ($screenMargin * 2)
    $screenH = [int]($phoneH * 0.72)
    $sx = $px + $screenMargin
    $sy = $py + $screenMargin
    $g.FillRectangle($bgBrush, $sx, $sy, $screenW, $screenH)

    # Home indicator line
    $lineY = $py + $phoneH - [int]($phoneH * 0.09)
    $lineW = [int]($phoneW * 0.3)
    $lx = $px + [int](($phoneW - $lineW) / 2)
    $pen = New-Object System.Drawing.Pen ([System.Drawing.Color]::White), ([Math]::Max(2, [int]($Size * 0.012)))
    $pen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
    $pen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
    $g.DrawLine($pen, $lx, $lineY, $lx + $lineW, $lineY)

    $bmp.Save($OutPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose()
    $bmp.Dispose()
}

$iconsDir = Join-Path $PSScriptRoot "..\static\icons"
New-Item -ItemType Directory -Force -Path $iconsDir | Out-Null

New-Icon -Size 192 -OutPath (Join-Path $iconsDir "icon-192.png") -Maskable $false
New-Icon -Size 512 -OutPath (Join-Path $iconsDir "icon-512.png") -Maskable $false
New-Icon -Size 512 -OutPath (Join-Path $iconsDir "icon-maskable-512.png") -Maskable $true

Write-Output "Icons written to $iconsDir"
