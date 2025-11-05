package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed templates/*
var templateFS embed.FS

var db *sql.DB
var templates *template.Template

// Models
type User struct {
	ID        int       `json:"id"`
	Username  string    `json:"username"`
	Password  string    `json:"-"` // Never send to client
	CreatedAt time.Time `json:"created_at"`
}

type Snippet struct {
	ID               int       `json:"id"`
	Title            string    `json:"title"`
	Content          string    `json:"content"`
	UserID           *int      `json:"user_id,omitempty"`
	EditPassword     string    `json:"edit_password,omitempty"` // For anonymous snippets
	VisibilityType   string    `json:"visibility_type"`         // public, private, password, link
	ViewPassword     string    `json:"-"`                       // For password-protected snippets
	UniqueLink       string    `json:"unique_link,omitempty"`   // For link-sharing
	CommentsEnabled  bool      `json:"comments_enabled"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
	Username         string    `json:"username,omitempty"`      // For display
	CommentCount     int       `json:"comment_count"`
}

type Comment struct {
	ID        int       `json:"id"`
	SnippetID int       `json:"snippet_id"`
	Username  string    `json:"username"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
}

type Session struct {
	UserID    int
	Username  string
	ExpiresAt time.Time
}

var sessions = make(map[string]Session)

// Database initialization
func initDB() error {
	var err error
	db, err = sql.Open("sqlite", "./pastebin.db")
	if err != nil {
		return err
	}

	// Create tables
	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS snippets (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		title TEXT DEFAULT '',
		content TEXT NOT NULL,
		user_id INTEGER,
		edit_password TEXT,
		visibility_type TEXT NOT NULL DEFAULT 'private',
		view_password TEXT,
		unique_link TEXT UNIQUE,
		comments_enabled INTEGER DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id)
	);

	CREATE TABLE IF NOT EXISTS comments (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		snippet_id INTEGER NOT NULL,
		username TEXT DEFAULT 'Anonymous',
		content TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (snippet_id) REFERENCES snippets(id) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS idx_snippets_visibility ON snippets(visibility_type);
	CREATE INDEX IF NOT EXISTS idx_snippets_unique_link ON snippets(unique_link);
	CREATE INDEX IF NOT EXISTS idx_comments_snippet ON comments(snippet_id);
	`

	_, err = db.Exec(schema)
	return err
}

// Utility functions
func hashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}

func generateRandomString(length int) string {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return ""
	}
	return hex.EncodeToString(bytes)[:length]
}

func getSessionUser(r *http.Request) *Session {
	cookie, err := r.Cookie("session")
	if err != nil {
		return nil
	}

	session, exists := sessions[cookie.Value]
	if !exists || time.Now().After(session.ExpiresAt) {
		return nil
	}

	return &session
}

func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session := getSessionUser(r)
		if session == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// Handlers
func homeHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	session := getSessionUser(r)

	data := map[string]interface{}{
		"LoggedIn": session != nil,
	}

	if session != nil {
		data["Username"] = session.Username
	}

	templates.ExecuteTemplate(w, "index.html", data)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if len(req.Username) < 3 || len(req.Password) < 6 {
		http.Error(w, "Username must be at least 3 characters and password at least 6 characters", http.StatusBadRequest)
		return
	}

	hashedPassword := hashPassword(req.Password)

	_, err := db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", req.Username, hashedPassword)
	if err != nil {
		http.Error(w, "Username already exists", http.StatusConflict)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"message": "Registration successful"})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	hashedPassword := hashPassword(req.Password)

	var user User
	err := db.QueryRow("SELECT id, username FROM users WHERE username = ? AND password = ?",
		req.Username, hashedPassword).Scan(&user.ID, &user.Username)

	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Create session
	sessionID := generateRandomString(32)
	sessions[sessionID] = Session{
		UserID:    user.ID,
		Username:  user.Username,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   86400, // 24 hours
	})

	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":  "Login successful",
		"username": user.Username,
	})
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err == nil {
		delete(sessions, cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:   "session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	json.NewEncoder(w).Encode(map[string]string{"message": "Logged out"})
}

func createSnippetHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Content          string `json:"content"`
		VisibilityType   string `json:"visibility_type"`
		ViewPassword     string `json:"view_password,omitempty"`
		CommentsEnabled  bool   `json:"comments_enabled"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.Content == "" {
		http.Error(w, "Content is required", http.StatusBadRequest)
		return
	}

	// Validate visibility type
	validTypes := map[string]bool{"public": true, "private": true, "password": true, "link": true}
	if !validTypes[req.VisibilityType] {
		req.VisibilityType = "private"
	}

	session := getSessionUser(r)

	var userID *int
	var editPassword *string
	var uniqueLink *string
	var viewPasswordHash *string

	if session != nil {
		userID = &session.UserID
	} else {
		// Anonymous post - generate edit password
		pwd := generateRandomString(16)
		editPassword = &pwd
	}

	// Generate unique link for link-sharing
	if req.VisibilityType == "link" {
		link := generateRandomString(12)
		uniqueLink = &link
	}

	// Hash view password if provided
	if req.VisibilityType == "password" && req.ViewPassword != "" {
		hash := hashPassword(req.ViewPassword)
		viewPasswordHash = &hash
	}

	result, err := db.Exec(`
		INSERT INTO snippets (content, user_id, edit_password, visibility_type, view_password, unique_link, comments_enabled)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		req.Content, userID, editPassword, req.VisibilityType, viewPasswordHash, uniqueLink, req.CommentsEnabled)

	if err != nil {
		log.Println("Error creating snippet:", err)
		http.Error(w, "Failed to create snippet", http.StatusInternalServerError)
		return
	}

	snippetID, _ := result.LastInsertId()

	response := map[string]interface{}{
		"id":      snippetID,
		"message": "Snippet created successfully",
	}

	if editPassword != nil {
		response["edit_password"] = *editPassword
		response["warning"] = "Save this password! You'll need it to edit this snippet later."
	}

	if uniqueLink != nil {
		response["unique_link"] = *uniqueLink
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func getPublicSnippetsHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`
		SELECT s.id, s.title, s.content, s.user_id, s.visibility_type, s.comments_enabled,
		       s.created_at, s.updated_at, u.username,
		       (SELECT COUNT(*) FROM comments WHERE snippet_id = s.id) as comment_count
		FROM snippets s
		LEFT JOIN users u ON s.user_id = u.id
		WHERE s.visibility_type = 'public'
		ORDER BY s.created_at DESC
	`)

	if err != nil {
		log.Println("Error fetching snippets:", err)
		http.Error(w, "Failed to fetch snippets", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	snippets := []Snippet{}
	for rows.Next() {
		var s Snippet
		var username sql.NullString

		err := rows.Scan(&s.ID, &s.Title, &s.Content, &s.UserID, &s.VisibilityType,
			&s.CommentsEnabled, &s.CreatedAt, &s.UpdatedAt, &username, &s.CommentCount)

		if err != nil {
			continue
		}

		if username.Valid {
			s.Username = username.String
		} else {
			s.Username = "Anonymous"
		}

		// Truncate content for list view
		if len(s.Content) > 200 {
			s.Content = s.Content[:200] + "..."
		}

		snippets = append(snippets, s)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(snippets)
}

func getSnippetHandler(w http.ResponseWriter, r *http.Request) {
	// Get snippet ID from URL
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		http.Error(w, "Invalid URL", http.StatusBadRequest)
		return
	}

	identifier := parts[3] // Could be ID or unique link

	var snippet Snippet
	var username sql.NullString
	var editPassword sql.NullString
	var viewPassword sql.NullString
	var uniqueLink sql.NullString
	var userID sql.NullInt64
	var query string
	var args []interface{}

	// Try to parse as ID first
	if id, err := strconv.Atoi(identifier); err == nil {
		query = `
			SELECT s.id, s.title, s.content, s.user_id, s.edit_password, s.visibility_type,
			       s.view_password, s.unique_link, s.comments_enabled, s.created_at, s.updated_at, u.username
			FROM snippets s
			LEFT JOIN users u ON s.user_id = u.id
			WHERE s.id = ?
		`
		args = []interface{}{id}
	} else {
		// Try as unique link
		query = `
			SELECT s.id, s.title, s.content, s.user_id, s.edit_password, s.visibility_type,
			       s.view_password, s.unique_link, s.comments_enabled, s.created_at, s.updated_at, u.username
			FROM snippets s
			LEFT JOIN users u ON s.user_id = u.id
			WHERE s.unique_link = ?
		`
		args = []interface{}{identifier}
	}

	err := db.QueryRow(query, args...).Scan(
		&snippet.ID, &snippet.Title, &snippet.Content, &userID, &editPassword,
		&snippet.VisibilityType, &viewPassword, &uniqueLink, &snippet.CommentsEnabled,
		&snippet.CreatedAt, &snippet.UpdatedAt, &username,
	)

	if err != nil {
		log.Println("Error fetching snippet:", err)
		http.Error(w, "Snippet not found", http.StatusNotFound)
		return
	}

	// Convert nullable fields
	if username.Valid {
		snippet.Username = username.String
	} else {
		snippet.Username = "Anonymous"
	}

	if userID.Valid {
		uid := int(userID.Int64)
		snippet.UserID = &uid
	}

	if editPassword.Valid {
		snippet.EditPassword = editPassword.String
	}

	if viewPassword.Valid {
		snippet.ViewPassword = viewPassword.String
	}

	if uniqueLink.Valid {
		snippet.UniqueLink = uniqueLink.String
	}

	session := getSessionUser(r)

	// Check access permissions
	canAccess := false

	switch snippet.VisibilityType {
	case "public":
		canAccess = true
	case "private":
		// Only owner can access
		if session != nil && snippet.UserID != nil && *snippet.UserID == session.UserID {
			canAccess = true
		}
	case "password":
		// Check if password provided
		password := r.URL.Query().Get("password")
		if password != "" && hashPassword(password) == snippet.ViewPassword {
			canAccess = true
		} else if session != nil && snippet.UserID != nil && *snippet.UserID == session.UserID {
			canAccess = true
		}
	case "link":
		// Already accessed via link or owner
		canAccess = true
		if session != nil && snippet.UserID != nil && *snippet.UserID == session.UserID {
			canAccess = true
		}
	}

	if !canAccess {
		if snippet.VisibilityType == "password" {
			http.Error(w, "Password required", http.StatusUnauthorized)
		} else {
			http.Error(w, "Access denied", http.StatusForbidden)
		}
		return
	}

	// Get comments
	comments := []Comment{}
	rows, err := db.Query(`
		SELECT id, snippet_id, username, content, created_at
		FROM comments
		WHERE snippet_id = ?
		ORDER BY created_at ASC
	`, snippet.ID)

	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var c Comment
			if err := rows.Scan(&c.ID, &c.SnippetID, &c.Username, &c.Content, &c.CreatedAt); err == nil {
				comments = append(comments, c)
			}
		}
	}

	// Don't send passwords to client
	snippet.ViewPassword = ""
	snippet.EditPassword = ""

	response := map[string]interface{}{
		"snippet":  snippet,
		"comments": comments,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func updateSnippetHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		http.Error(w, "Invalid URL", http.StatusBadRequest)
		return
	}

	snippetID, err := strconv.Atoi(parts[4])
	if err != nil {
		log.Println("Invalid snippet ID:", parts[4])
		http.Error(w, "Invalid snippet ID", http.StatusBadRequest)
		return
	}

	var req struct {
		Content      string `json:"content"`
		EditPassword string `json:"edit_password,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.Content == "" {
		http.Error(w, "Content is required", http.StatusBadRequest)
		return
	}

	// Check ownership
	var userID sql.NullInt64
	var editPassword sql.NullString
	err = db.QueryRow("SELECT user_id, edit_password FROM snippets WHERE id = ?", snippetID).
		Scan(&userID, &editPassword)

	if err != nil {
		http.Error(w, "Snippet not found", http.StatusNotFound)
		return
	}

	session := getSessionUser(r)
	canEdit := false

	// Check if user owns it
	if session != nil && userID.Valid && int(userID.Int64) == session.UserID {
		canEdit = true
	} else if editPassword.Valid && req.EditPassword == editPassword.String {
		// Check anonymous edit password
		canEdit = true
	}

	if !canEdit {
		http.Error(w, "Unauthorized to edit this snippet", http.StatusForbidden)
		return
	}

	_, err = db.Exec(`
		UPDATE snippets
		SET content = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, req.Content, snippetID)

	if err != nil {
		http.Error(w, "Failed to update snippet", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"message": "Snippet updated successfully"})
}

func deleteSnippetHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		http.Error(w, "Invalid URL", http.StatusBadRequest)
		return
	}

	snippetID, err := strconv.Atoi(parts[4])
	if err != nil {
		log.Println("Invalid snippet ID:", parts[4])
		http.Error(w, "Invalid snippet ID", http.StatusBadRequest)
		return
	}

	// Check ownership
	var userID sql.NullInt64
	var editPassword sql.NullString
	err = db.QueryRow("SELECT user_id, edit_password FROM snippets WHERE id = ?", snippetID).
		Scan(&userID, &editPassword)

	if err != nil {
		http.Error(w, "Snippet not found", http.StatusNotFound)
		return
	}

	session := getSessionUser(r)
	canDelete := false

	// Check if user owns it
	if session != nil && userID.Valid && int(userID.Int64) == session.UserID {
		canDelete = true
	} else {
		// Check for edit password in query parameter
		editPwd := r.URL.Query().Get("edit_password")
		if editPwd != "" && editPassword.Valid && editPwd == editPassword.String {
			canDelete = true
		}
	}

	if !canDelete {
		http.Error(w, "Unauthorized to delete this snippet", http.StatusForbidden)
		return
	}

	_, err = db.Exec("DELETE FROM snippets WHERE id = ?", snippetID)
	if err != nil {
		http.Error(w, "Failed to delete snippet", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"message": "Snippet deleted successfully"})
}

func createCommentHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		SnippetID int    `json:"snippet_id"`
		Content   string `json:"content"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Check if comments are enabled
	var commentsEnabled bool
	err := db.QueryRow("SELECT comments_enabled FROM snippets WHERE id = ?", req.SnippetID).
		Scan(&commentsEnabled)

	if err != nil {
		http.Error(w, "Snippet not found", http.StatusNotFound)
		return
	}

	if !commentsEnabled {
		http.Error(w, "Comments are disabled for this snippet", http.StatusForbidden)
		return
	}

	_, err = db.Exec(`
		INSERT INTO comments (snippet_id, content)
		VALUES (?, ?)
	`, req.SnippetID, req.Content)

	if err != nil {
		http.Error(w, "Failed to create comment", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"message": "Comment added successfully"})
}

func getUserSnippetsHandler(w http.ResponseWriter, r *http.Request) {
	session := getSessionUser(r)
	if session == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	rows, err := db.Query(`
		SELECT id, title, content, visibility_type, comments_enabled, created_at, updated_at,
		       (SELECT COUNT(*) FROM comments WHERE snippet_id = snippets.id) as comment_count
		FROM snippets
		WHERE user_id = ?
		ORDER BY created_at DESC
	`, session.UserID)

	if err != nil {
		http.Error(w, "Failed to fetch snippets", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	snippets := []Snippet{}
	for rows.Next() {
		var s Snippet
		err := rows.Scan(&s.ID, &s.Title, &s.Content, &s.VisibilityType,
			&s.CommentsEnabled, &s.CreatedAt, &s.UpdatedAt, &s.CommentCount)

		if err != nil {
			continue
		}

		s.Username = session.Username

		// Truncate content
		if len(s.Content) > 200 {
			s.Content = s.Content[:200] + "..."
		}

		snippets = append(snippets, s)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(snippets)
}

func viewSnippetPageHandler(w http.ResponseWriter, r *http.Request) {
	// Get snippet ID from URL
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 3 {
		http.Error(w, "Invalid URL", http.StatusBadRequest)
		return
	}

	identifier := parts[2] // Could be ID or unique link

	var snippet Snippet
	var username sql.NullString
	var editPassword sql.NullString
	var viewPassword sql.NullString
	var uniqueLink sql.NullString
	var userID sql.NullInt64
	var query string
	var args []interface{}

	// Try to parse as ID first
	if id, err := strconv.Atoi(identifier); err == nil {
		query = `
			SELECT s.id, s.title, s.content, s.user_id, s.edit_password, s.visibility_type,
			       s.view_password, s.unique_link, s.comments_enabled, s.created_at, s.updated_at, u.username
			FROM snippets s
			LEFT JOIN users u ON s.user_id = u.id
			WHERE s.id = ?
		`
		args = []interface{}{id}
	} else {
		// Try as unique link
		query = `
			SELECT s.id, s.title, s.content, s.user_id, s.edit_password, s.visibility_type,
			       s.view_password, s.unique_link, s.comments_enabled, s.created_at, s.updated_at, u.username
			FROM snippets s
			LEFT JOIN users u ON s.user_id = u.id
			WHERE s.unique_link = ?
		`
		args = []interface{}{identifier}
	}

	err := db.QueryRow(query, args...).Scan(
		&snippet.ID, &snippet.Title, &snippet.Content, &userID, &editPassword,
		&snippet.VisibilityType, &viewPassword, &uniqueLink, &snippet.CommentsEnabled,
		&snippet.CreatedAt, &snippet.UpdatedAt, &username,
	)

	if err != nil {
		log.Println("Error fetching snippet:", err)
		http.Error(w, "Snippet not found", http.StatusNotFound)
		return
	}

	// Convert nullable fields
	if username.Valid {
		snippet.Username = username.String
	} else {
		snippet.Username = "Anonymous"
	}

	if userID.Valid {
		uid := int(userID.Int64)
		snippet.UserID = &uid
	}

	if editPassword.Valid {
		snippet.EditPassword = editPassword.String
	}

	if viewPassword.Valid {
		snippet.ViewPassword = viewPassword.String
	}

	if uniqueLink.Valid {
		snippet.UniqueLink = uniqueLink.String
	}

	session := getSessionUser(r)

	// Check access permissions
	canAccess := false

	switch snippet.VisibilityType {
	case "public":
		canAccess = true
	case "private":
		// Only owner can access
		if session != nil && snippet.UserID != nil && *snippet.UserID == session.UserID {
			canAccess = true
		}
	case "password":
		// Check if password provided
		password := r.URL.Query().Get("password")
		if password != "" && hashPassword(password) == snippet.ViewPassword {
			canAccess = true
		} else if session != nil && snippet.UserID != nil && *snippet.UserID == session.UserID {
			canAccess = true
		}
	case "link":
		// Already accessed via link or owner
		canAccess = true
		if session != nil && snippet.UserID != nil && *snippet.UserID == session.UserID {
			canAccess = true
		}
	}

	if !canAccess {
		if snippet.VisibilityType == "password" {
			http.Error(w, "Password required", http.StatusUnauthorized)
		} else {
			http.Error(w, "Access denied", http.StatusForbidden)
		}
		return
	}

	// Get comments
	comments := []Comment{}
	rows, err := db.Query(`
		SELECT id, snippet_id, username, content, created_at
		FROM comments
		WHERE snippet_id = ?
		ORDER BY created_at ASC
	`, snippet.ID)

	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var c Comment
			if err := rows.Scan(&c.ID, &c.SnippetID, &c.Username, &c.Content, &c.CreatedAt); err == nil {
				comments = append(comments, c)
			}
		}
	}

	// Check if user can edit
	canEdit := false
	isOwner := false
	canDelete := false

	if session != nil && snippet.UserID != nil && *snippet.UserID == session.UserID {
		canEdit = true
		isOwner = true
		canDelete = true
	} else if snippet.EditPassword != "" {
		canEdit = true // Can edit with password
		canDelete = true // Can also delete with password
	}

	data := map[string]interface{}{
		"Snippet":   snippet,
		"Comments":  comments,
		"CanEdit":   canEdit,
		"IsOwner":   isOwner,
		"CanDelete": canDelete,
	}

	templates.ExecuteTemplate(w, "snippet.html", data)
}

func main() {
	// Initialize database
	if err := initDB(); err != nil {
		log.Fatal("Failed to initialize database:", err)
	}
	defer db.Close()

	// Parse templates
	var err error
	templates, err = template.ParseFS(templateFS, "templates/*.html")
	if err != nil {
		log.Fatal("Failed to parse templates:", err)
	}

	// Routes
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/snippet/", viewSnippetPageHandler)       // View snippet page
	http.HandleFunc("/api/register", registerHandler)
	http.HandleFunc("/api/login", loginHandler)
	http.HandleFunc("/api/logout", logoutHandler)
	http.HandleFunc("/api/snippets/create", createSnippetHandler)
	http.HandleFunc("/api/snippets/public", getPublicSnippetsHandler)
	http.HandleFunc("/api/snippets/my", getUserSnippetsHandler)
	http.HandleFunc("/api/snippets/", getSnippetHandler)       // GET single snippet (API)
	http.HandleFunc("/api/snippet/update/", updateSnippetHandler) // PUT update
	http.HandleFunc("/api/snippet/delete/", deleteSnippetHandler) // DELETE
	http.HandleFunc("/api/comments/create", createCommentHandler)

	port := ":8080"
	log.Printf("Server starting on http://localhost%s", port)
	log.Fatal(http.ListenAndServe(port, nil))
}
