function main()
    local whitelist = {
            "^/login",
            "^/logout",
            "^/health"
        }
    for _, pattern in ipairs(whitelist) do
        print(pattern)
    end
    return nil
end