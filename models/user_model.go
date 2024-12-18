package models

import "github.com/google/uuid"

type UserToAuth struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type EmailType struct {
	Subject  string `json:"subject"`
	Message  string `json:"message"`
	Reciever string `json:"reciever"`
}

type User struct {
	ID       uuid.UUID `json:"id"`
	Email    string    `json:"email"`
	Password string    `json:"password"`
	Name     string    `json:"name"`
}
