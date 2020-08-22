require 'matrix'

$AES_modulus = '100011011'.to_i(2)

def makeSubTables()
  subBytesTable = Matrix.build(16,16) {0}
  invSubBytesTable = Matrix.build(16,16) {0}

  subBytesfile = open("subtable.txt","r").read.split
  subBytesfileInv = open("subtabInverse.txt","r").read.split

  for i in 0..15
    for j in 0..15
      subBytesTable[i,j] =  subBytesfile[i + 16*j]
      invSubBytesTable[i,j] = subBytesfileInv[i + 16*j].to_i(16)
    end
  end
  return subBytesTable , invSubBytesTable
end
