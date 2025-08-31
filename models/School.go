package models

type School struct {
	ID             int
	IdemisCode     string `gorm:"column:idemis_code"`
	Idregion       string `gorm:"column:idregion"`
	Region         string `gorm:"column:region"`
	Iddistrict     string `gorm:"column:iddistrict"`
	District       string `gorm:"column:district"`
	Idcouncil      string `gorm:"column:idcouncil"`
	Council        string `gorm:"column:council"`
	Idchiefdom     string `gorm:"column:idchiefdom"`
	Chiefdom       string `gorm:"column:chiefdom"`
	Section        string `gorm:"column:section"`
	Town           string `gorm:"column:town"`
	SchoolName     string `gorm:"column:school_name"`
	IdschType      string `gorm:"column:idsch_type"`
	SchType        string `gorm:"column:sch_type"`
	ShiftStatus    string `gorm:"column:shift_status"`
	IdshiftStatus  string `gorm:"column:idshift_status"`
	IdschoolStatus string `gorm:"column:idschool_status"`
	SchoolStatus   string `gorm:"column:school_status"`
	Approval       string `gorm:"column::approval"`
	SchOwner       string `gorm:"column::sch_owner"`
	GeopointLong   string `gorm:"column:geopoint-Longitude"`
	GeopointLat    string `gorm:"column:geopoint-Latitude"`
}

// TableName sets the insert table name for this struct type
func (School) School() string {
	return "schools"
}
