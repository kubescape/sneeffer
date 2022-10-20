package DB

type DBClientInterface interface {
	SetDataInDB(data []byte) bool
	GetDataFromDB(key []byte) []byte
}
