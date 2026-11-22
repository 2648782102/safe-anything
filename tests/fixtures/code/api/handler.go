cmd := exec.Command("sh", "-c", userCmd)
cmd := exec.Command("git", "log")
q := fmt.Sprintf("SELECT * FROM users WHERE id = %s", id)
tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
h := md5.New()
