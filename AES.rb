require './subBox'
require 'matrix'
class AES


  def self.decrypt_to_ascii(text, hexKey , encryptionType)
    hex_text = self.decrypt_hex(text , hexKey , encryptionType)
    if(hex_text.length % 2 != 0)
      hex_text = '0' + hex_text
    end
    tmp = (hex_text.each_char.map{|x| x}).each_slice(2).map{ |x| x.join.to_i(16).chr}
    return tmp.join()
  end



  def self.encrypt_ascii(text, hexKey , encryptionType)
    text1 = text.each_char.map{|x| self.makeLen(x.ord.to_s(16) , 2)}
    return self.encrypt_hex(text1.join , hexKey , encryptionType)
  end


  def self.encrypt_hex( text , hexKey , encryptionType)
    _ , binKey , byteArrKey = self.makeKey(hexKey, encryptionType)
    textArr = self.make16ByteChunk(text)
    textMatArr = textArr.each.map{ |x| self.makeMatrix(x)}
    if(encryptionType==128)
      self.generateFor128()
      round =10
    elsif(encryptionType == 192)
      self.generateFor192
      round = 12
    elsif(encryptionType == 256)
      self.generateFor256
      round = 14
    else
      throw "Invalid encryptionType"
      return 0
    end

    return self.encrypt(textMatArr,binKey,round)
  end


  def self.decrypt_hex(text , hexKey , encryptionType)
    _ , binKey , byteArrKey = self.makeKey(hexKey, encryptionType)
    textArr = self.make16ByteChunk(text)
    textMatArr = textArr.each.map{ |x| self.makeMatrix(x)}
    if(encryptionType==128)
      self.generateFor128()
      round =10
    elsif(encryptionType == 192)
      self.generateFor192
      round = 12
    elsif(encryptionType == 256)
      self.generateFor256
      round = 14
    else
      throw "Invalid encryptionType"
      return 0
    end
    return self.decrypt(textMatArr , binKey, round)
  end





  @W =[]

  InvMixColMatrix = Matrix[[14,11,13,9],[9,14,11,13],[13,9,14,11],[11,13,9,14]]
  MixColMat = Matrix[[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]]
  SubTable , SubTableInv = makeSubTables()
  Rc = [1,2,4,8,16,32,64,128,27,54]
  RCon = Rc.each.map{|x| [x.to_s(2),'0'*8,'0'*8,'0'*8]}



  # Gets rc for Round constant RCon = [rc 0 0 0] for 128 bit key
  def self.get_rc(i,rc)
    if(i==0)
      return 1
    elsif(i>0 and rc[i-1]<('80'.to_i(16)))
      return 2*rc[i-1]
    elsif(i>1 and rc[i-1] >= '80'.to_i(16))
      return (2*rc[i-1]) ^ '11B'.to_i(16)
    end
  end

  # Gets the entire arr for rc given a parameter
  # Gets called with 9 for 128  bit encryption
  # Should be called with 11 for 192 and 13 for 256
  def self.get_rc_array(i)
    rc=[]
    for i in 0..i
      rc << self.get_rc(i,rc)
    end
    rc
  end


  def self.makeKey(hexKey, encryptionType)
    tmp = hexKey.each_char.map{|x| self.makeLen(x.to_i(16).to_s(2), 4)}
    tmp2 = tmp.join
    binKey = tmp2 + '0'*(encryptionType - (tmp2.length))
    # THis is for round key generation
    byteKeyArr = (binKey.each_char.map {|y| y }).each_slice(8).map{|x| x.join }
    y = []
    byteKeyArr.each_slice(4){
      |x|
      y << x
    }
    @W = y
    return hexKey, binKey , byteKeyArr 
  end



  def self.makeLen(a,len)
    return '0'*(len - a.length) + a
  end

  def self.makeLen8(a)
    return makeLen(a,8)
  end

  #Used for key generation and AddRoundKey
  def self.xorTwoWords(w1, w2)
    arr=[]
    4.times do
      |x|
      arr << self.makeLen8(((w1[x].to_s.to_i(2)) ^ (w2[x].to_s.to_i(2))).to_s(2))
    end
    return arr
  end


  ## substitutes the word from subtable or subtableinv
  def self.subWord(word, enc=true)
    x,y = (makeLen8(word).each_char.map{|x| x}).each_slice(4).map{|y|  (y.join).to_i(2) }
    if(enc)
      return SubTable[x,y].to_i.to_s(2)
    else
      return SubTableInv[x,y].to_i.to_s(2)
    end
  end

  # Used in round key generation
  def self.gMethod(word4byteArr,i)
    tmp= (self.rotWord(word4byteArr)).each.map{ |x| self.subWord(x)}
    return [((tmp[0].to_i(2)) ^ (RCon[i-1][0].to_i(2))).to_s(2), tmp[1],tmp[2], tmp[3]]
  end

  #key generate. Assumes first 4 are already generated
  def self.generateFor128()
    for i in 4..43
      if(i%4 == 0)
        @W << self.xorTwoWords( @W[((i-1)/4)*4] , self.gMethod( @W[-1] , i/4 ) )
      else
        @W << self.xorTwoWords( @W[-1] , @W[i-4] )
      end
    end
  end

  def self.generateFor192()
    for i in 6..51
      if(i%6 == 0)
        @W << self.xorTwoWords( @W[((i-6)/6)*6],self.gMethod(@W[-1], i/6))
      else
        @W << self.xorTwoWords(@W[-1], @W[i-6])
      end
    end
  end

  def self.generateFor256()
    for i in 8..59
      if(i%8 == 0)
        @W << self.xorTwoWords( @W[((i-8)/8)*8] , self.gMethod(@W[-1] , i/8) )
      else
        @W << self.xorTwoWords(@W[-1], @W[i-8])
      end
    end
  end



  # Mixes the columns by multiply with MixColMat or InvMixColMatrix
  def self.mixColumn(a,b)
    return self.multiply(a,b)
  end



  def self.substituteBytes(mats , enc = true)
    newMat =[]
    for mat in mats
      tmp1 = self.getColumnAsArray(mat)
      tmp2 = tmp1.each.map{ |x| x.each.map{ |y| self.subWord(y , enc)}}
      newMat << self.get2DArrAsMatrix(tmp2)
    end
    return newMat
  end



  # encrypt function starts here
  #
  def self.encrypt(textMatArr , key, rounds)
    encMat = []
    for mat in textMatArr
      encMat << self.get2DArrAsMatrix(self.AddRoundKey(self.getColumnAsArray(mat), @W[..3]))
    end
    for i in 1..rounds
      encMat1 = self.substituteBytes(encMat)
      encMat2 = encMat1.each.map { |x| self.shiftrowForward(x)}
      if(i == rounds)
          encMat3 = encMat2
      else
        encMat3 = encMat2.each.map { |x| self.mixColumn(x,MixColMat) }
      end
      encMat = encMat3.each.map { |x|  self.get2DArrAsMatrix(self.AddRoundKey(self.getColumnAsArray(x),@W[(i*4)..((i*4) + 3)]))}
    end
    encMat = encMat.each.map {|x| self.getColumnAsArray(x)}
    encMat.flatten!
    encMat = encMat.each.map{|x| self.makeLen(x.to_i(2).to_s(16),2)}
    return encMat.join
  end



  # decrypt function starts here
  #
  def self.decrypt(textMatArr , key, rounds)
    decMat = []
    for mat in textMatArr
      decMat << self.get2DArrAsMatrix(self.AddRoundKey(self.getColumnAsArray(mat), @W[(rounds*4)..(rounds*4+3)]))
    end
    for i in ((rounds-1)..1).step(-1)
      decMat1 = decMat.each.map { |x| self.shiftRowBackward(x)}
      decMat2 = self.substituteBytes(decMat1 , enc = false)
      decMat3 = decMat2.each.map { |x|  self.get2DArrAsMatrix(self.AddRoundKey(self.getColumnAsArray(x),@W[(i*4)..((i*4) + 3)]))}
      decMat = decMat3.each.map { |x| self.mixColumn(x,InvMixColMatrix) }
    end
    decMat1 = decMat.each.map{|x| self.shiftRowBackward(x)}
    decMat2 = self.substituteBytes(decMat1 , enc=false)
    decMat = decMat2.each.map{|x| self.get2DArrAsMatrix(self.AddRoundKey(self.getColumnAsArray(x),@W[..3]))}

    decMat = decMat.each.map {|x| self.getColumnAsArray(x)}
    decMat.flatten!
    decMat = decMat.each.map{|x| self.makeLen(x.to_i(2).to_s(16),2)}
    decMat= decMat.join
    decMat.sub(/^(0)*/, '')
  end




  # Flattens the list of matrix and presents everything in hex
  def self.printMatHex(mat)
    x = mat.each.map{|x| self.getColumnAsArray(x)}
    x.flatten!
    x = x.each.map{|y| self.makeLen(y.to_i(2).to_s(16),2)}
    return x
  end


  # Row shift inverse
  def self.shiftRowBackward(mat)
    arr = Matrix.zero(4)
    for i in 0..3
      for j in 0..3
        arr[i,j] = mat[i,(j-i) % 4 ]
      end
    end
    arr
  end

  # Row shift for encryption
  def self.shiftrowForward(mat)
    arr=Matrix.zero(4)
    for i in 0..3
      for j in 0..3
        arr[i,j] = mat[i, (i+j) % 4]
      end
    end
    return arr
  end


  # Takes a matrix
  # Turns it into an 2darray which has the column in each each entry
  # Example Matrix[[1,2],[3,4] -> [[1,3],[2,4]
  def self.getColumnAsArray(a)
    arr =[ [], [], [], [] ]
    for i in 0..3
      for j in 0..3
        arr[j] << a[i,j]
      end
    end
    arr
  end

  # Basically the inverse of getColumnAsArray function
  # [[1,3],[2,4]] -> Matrix[[1,2],[3,4]]
  def self.get2DArrAsMatrix(arr)
    a=Matrix.build(4) {0}
    for i in 0..3
      for j in 0..3
        a[i,j] = arr[j][i]
      end
    end
    a
  end


  # Method to add round key. Xors a and b where a and b are arrays
  # a = [b1,b2,b3,b4] where b1,b2,b3,b4 are 8 are treated as 1 byte
  def self.AddRoundKey(a , b)
    arr=[]
    4.times do
      |x|
      arr <<  self.xorTwoWords( a[x], b[x])
    end
    return arr
  end


  # Rotates the given array. Used for round key generation
  def self.rotWord(arr)
    return [arr[1],arr[2],arr[3],arr[0]]
  end


  #Converts a given hex string to chunks of 16bytes
  # 'abcdef0123456789' -> ['0','0','0','0','0','0','0','0','ab','cd','ef','01','23', '45','67','89']
  def self.make16ByteChunk(str)
    len = str.length
    if( len % 32 != 0)
      pad = ((len/32)+1)*32 - len
    else
      pad=0
    end
    arr = ( '0' * pad) + str
    return2dArr=[]
    arr2 = arr.each_char.map{|x| x }
    arr2.each_slice(32){
      |x|
      return2dArr << x.each_slice(2).map{|x| self.makeLen8(x.join.to_i(16).to_s(2))}
    }
    return return2dArr
  end

  # Makes  matrix in column major order of the giver 16 bytes
  # Used in Mix Column step
  def self.makeMatrix(arr)
    mat = Matrix.zero(4)
    for i in 0..3
      for j in 0..3
        mat[i,j] = arr[i + 4*j]
      end
    end
    return mat
  end


  #  Multiply method that will be used. Uses xor instead of + and mul function instead of '*'
  #  mul function is some complex stuff but  it works
  #  Helper for mix column
  # a is always matrix with bitstrings while b is InvMixColMatrix or MixColMat
  def self.multiply(a,b)
    if(a.column_size != b.row_size )
      throw "Multiplication error"
    else
      a,b = b,a
      row = a.row_size
      col = b.column_size
      mat = Matrix.build(row,col) {0}
      row.times {
        |i|
        col.times{
          |j|
          (a.column_size).times{
            |k|
            mat[i,j] = (((mat[i,j])) ^ (self.mul((a[i,k]),(b[k,j]).to_i(2))))
          }
          mat[i,j] = mat[i,j].to_s(2)
        }
      }
      return mat
    end
  end


  # Dont ask why this works
  # This just works
  # Learn Galois Field Theory to understand this which i dont know yet
  def self.mul(x,y)
    mod = 283
    temp = y
    ans = 0
    for i in 0..7
      if ((( 1 << i) & x) != 0)
        ans = ans ^ (temp << i)
      end
    end
    for j in (15..8).step(-1)
      if ((ans & (1 << j)) != 0)
        ans = ans ^ (mod << (j-8))
      end
    end
    a = ans.to_s(2)
    if(a.length > 8)
      return ((a[(a.length - 8)..]).to_i(2))
    else
      return ans
    end
  end

end
