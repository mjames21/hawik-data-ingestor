package database

import (
	"gitlab.com/tymonx/go-formatter/formatter"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func Mysql(db_username string, db_password string, db_database string, db_host string, db_port string) *gorm.DB {
	// connection. string
	db_connection, err := formatter.Format("{db_username}:{db_password}@tcp({db_host}:{db_port})/{db_database}", formatter.Named{"db_host": db_host, "db_username": db_username, "db_password": db_password, "db_database": db_database, "db_port": db_port})
	if err != nil {
		panic(err)
	}

	connection, err := gorm.Open(mysql.Open(db_connection), &gorm.Config{})
	if err != nil {
		panic("could not connect to the database")
	}
	return connection
}
