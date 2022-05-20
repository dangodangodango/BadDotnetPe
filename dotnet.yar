import "dotnet"

rule dotnet_version_rule
{
    condition:
        dotnet.version == "v4.0.30319"
}
