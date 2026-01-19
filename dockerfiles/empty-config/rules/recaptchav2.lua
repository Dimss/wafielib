function main()
    print("RUNNING RECAPTCHA v2 script")
    local token = m.getvar("ARGS_POST:g-recaptcha-response")
    print("token: " .. token)
    return nil
end