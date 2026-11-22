var cmd = new SqlCommand("SELECT * FROM Users WHERE Id = " + id, conn);
var cmd2 = new SqlCommand($"SELECT * FROM Users WHERE Id = {id}", conn);
var f = new BinaryFormatter();
