# Cache Manager Module
# Provides caching to reduce repeated expensive operations

$script:SignatureCache = @{}
$script:HashCache = @{}
$script:ProcessCache = @{}
$script:LastCacheClean = Get-Date

function Get-CachedSignature {
    param([string]$FilePath)
    
    $now = Get-Date
    $ttl = 60 # minutes
    
    if ($script:SignatureCache.ContainsKey($FilePath)) {
        $cached = $script:SignatureCache[$FilePath]
        if (($now - $cached.Timestamp).TotalMinutes -lt $ttl) {
            return $cached.Value
        }
    }
    
    try {
        $sig = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction SilentlyContinue
        $script:SignatureCache[$FilePath] = @{
            Value = $sig
            Timestamp = $now
        }
        return $sig
    } catch {
        return $null
    }
}

function Get-CachedFileHash {
    param(
        [string]$FilePath,
        [string]$Algorithm = "MD5"
    )
    
    $now = Get-Date
    $ttl = 120 # minutes
    $key = "$FilePath|$Algorithm"
    
    if ($script:HashCache.ContainsKey($key)) {
        $cached = $script:HashCache[$key]
        $fileInfo = Get-Item $FilePath -ErrorAction SilentlyContinue
        if ($fileInfo -and $cached.LastWrite -eq $fileInfo.LastWriteTime -and ($now - $cached.Timestamp).TotalMinutes -lt $ttl) {
            return $cached.Value
        }
    }
    
    try {
        $fileInfo = Get-Item $FilePath -ErrorAction SilentlyContinue
        if (-not $fileInfo) { return $null }
        
        $hash = (Get-FileHash -Path $FilePath -Algorithm $Algorithm -ErrorAction SilentlyContinue).Hash
        $script:HashCache[$key] = @{
            Value = $hash
            Timestamp = $now
            LastWrite = $fileInfo.LastWriteTime
        }
        return $hash
    } catch {
        return $null
    }
}

function Clear-ExpiredCache {
    $now = Get-Date
    
    if (($now - $script:LastCacheClean).TotalMinutes -lt 30) {
        return
    }
    
    $script:LastCacheClean = $now
    
    # Clean signature cache
    $expiredSigs = $script:SignatureCache.Keys | Where-Object {
        ($now - $script:SignatureCache[$_].Timestamp).TotalMinutes -gt 60
    }
    foreach ($key in $expiredSigs) {
        $script:SignatureCache.Remove($key)
    }
    
    # Clean hash cache
    $expiredHashes = $script:HashCache.Keys | Where-Object {
        ($now - $script:HashCache[$_].Timestamp).TotalMinutes -gt 120
    }
    foreach ($key in $expiredHashes) {
        $script:HashCache.Remove($key)
    }
}

# Note: This script is dot-sourced by other agents. Export-ModuleMember is not used
# because it only works in .psm1 modules; dot-sourcing makes all functions available.
