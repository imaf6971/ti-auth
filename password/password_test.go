package password

import "testing"

func TestVerifyPassword(t *testing.T) {
	encodedHashHello123, _ := GenerateHashFromPassword("hello123", DefaultParams())
	type args struct {
		password    string
		encodedHash string
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "matching passwords return true",
			args: args{
				password:    "hello123",
				encodedHash: encodedHashHello123,
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "unmatching passwords return false",
			args: args{
				password:    "123hello",
				encodedHash: encodedHashHello123,
			},
			want:    false,
			wantErr: false,
		},
		{
			name: "Trash encodedHash value returns error",
			args: args{
				password:    "someUsualPassword",
				encodedHash: "trashhash",
			},
			want:    false,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := VerifyPassword(tt.args.password, tt.args.encodedHash)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyPassword() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("VerifyPassword() = %v, want %v", got, tt.want)
			}
		})
	}
}
