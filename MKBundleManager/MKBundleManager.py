#!/usr/bin/env python
# coding=utf-8
# by BinSys <binsys@163.com>

# 支持 mtouch mtouch-64 mtouch.exe mandroid.exe 解包

# Readme

# 1. 将插件文件 MKBundleManager.py 放入 IDA Pro 的 plugins 目录
# 2. 用IDA打开待分析文件，等待分析完毕(左下角状态栏的 AU: idel)
# 3. IDA 菜单栏 点击 View -> Open subviews -> Bundled Assembly Manager
# 4. 在 Bundled Assembly Manager 窗口中可见程序集列表
# 5. 选择要修改的文件用右键菜单内 导出全部文件 或者 导出文件 命令导出到指定位置
# 6. 文件修改完毕后用右键菜单内 替换文件 命令 替换修改后的文件
# 7. 会在位于原程序所在目录内用原文件名+日期时间命名生成替换后的打包文件

# Note:
# 可能会存在问题，请看IDA的输出窗口获取详细出错信息
# .Net 程序集的修改可用 替换文件Radate .NET Reflector + Reflexil 插件
# 当修改后的文件被压缩后大于原始文件的压缩数据大小时无法替换，这时，请用Reflexil删除修改后的程序集的冗余IL指令，减少程序集大小




MKBundleManager_VERSION = "1.2"

# IDA libraries
import idaapi
import idautils
import idc
from idaapi import Form, Choose2, plugin_t

# Python modules
import io
import sys
import os
import shutil
import struct
import binascii
from datetime import datetime, date, time
import urllib2
import httplib
import zlib
import StringIO
import gzip
import traceback

from struct import *



InputFileType_EXE = 11
InputFileType_MachO = 25
InputFileType = -1

Is64Bit = False


string_type_map = {
	0 : "ASCSTR_C",       #              C-string, zero terminated
	1 : "ASCSTR_PASCAL",  #              Pascal-style ASCII string (length byte)
	2 : "ASCSTR_LEN2",    #              Pascal-style, length is 2 bytes
	3 : "ASCSTR_UNICODE", #              Unicode string
	4 : "ASCSTR_LEN4",    #              Delphi string, length is 4 bytes
	5 : "ASCSTR_ULEN2",   #              Pascal-style Unicode, length is 2 bytes
	6 : "ASCSTR_ULEN4",   #              Pascal-style Unicode, length is 4 bytes
}




filetype_t_map = {
	 0 : "f_EXE_old",            # MS DOS EXE File
	 1 : "f_COM_old",            # MS DOS COM File
	 2 : "f_BIN",                # Binary File
	 3 : "f_DRV",                # MS DOS Driver
	 4 : "f_WIN",                # New Executable (NE)
	 5 : "f_HEX",                # Intel Hex Object File
	 6 : "f_MEX",                # MOS Technology Hex Object File
	 7 : "f_LX",                 # Linear Executable (LX)
	 8 : "f_LE",                 # Linear Executable (LE)
	 9 : "f_NLM",                # Netware Loadable Module (NLM)
	10 : "f_COFF",               # Common Object File Format (COFF)
	11 : "f_PE",                 # Portable Executable (PE)
	12 : "f_OMF",                # Object Module Format
	13 : "f_SREC",               # R-records
	14 : "f_ZIP",                # ZIP file (this file is never loaded to IDA database)
	15 : "f_OMFLIB",             # Library of OMF Modules
	16 : "f_AR",                 # ar library
	17 : "f_LOADER",             # file is loaded using LOADER DLL
	18 : "f_ELF",                # Executable and Linkable Format (ELF)
	19 : "f_W32RUN",             # Watcom DOS32 Extender (W32RUN)
	20 : "f_AOUT",               # Linux a.out (AOUT)
	21 : "f_PRC",                # PalmPilot program file
	22 : "f_EXE",                # MS DOS EXE File
	23 : "f_COM",                # MS DOS COM File
	24 : "f_AIXAR",              # AIX ar library
	25 : "f_MACHO",              # Max OS X
}

class BundledAssembly():
	def __init__(self):
		self.Index = 0
		self.FileItemStructOffset = 0
		self.FileNameOffset = 0
		self.FileName = ""
		self.FileDataOffset = 0
		self.FileSize = 0
		self.FileSizeOffset = 0
		self.FileCompressedSizeOffset = 0
		self.FileCompressedSize = 0
		self.IsGZip = ""
		self.FileDataCompressed = ""
		self.IsCompressed = True
		self.IsME = False

		pass

class MKBundleTool():
	def __init__(self):
		self.Is64Bit = False
		self.InputFileType = -1

		print("Input File:{}".format(GetInputFile()))
		print("Input File Path:{}".format(GetInputFilePath()))
		print("Idb File Path:{}".format(GetIdbPath()))
		print("cpu_name:{}".format(idc.GetShortPrm(idc.INF_PROCNAME).lower()))
	
		self.InputFileType = idc.GetShortPrm(idc.INF_FILETYPE)
		#ida.hpp filetype_t f_PE=11 f_MACHO=25
	
		print("InputFileType:{}".format(filetype_t_map.get(self.InputFileType, None)))
	
	
		if self.InputFileType != InputFileType_EXE and self.InputFileType != InputFileType_MachO:
			print "Error,Input file type must is PE or MachO!"
			return
		
	
	
	
		if (idc.GetShortPrm(idc.INF_LFLAGS) & idc.LFLG_64BIT) == idc.LFLG_64BIT:
			self.Is64Bit = True
		else:
			self.Is64Bit = False
		
		print("Is64Bit:{}".format(self.Is64Bit))


	def GetBundledAssemblyList(self,UseScreenEA = False):

		if not UseScreenEA:


			StringEA = self.FindStringEA()
			if StringEA == -1:
				print "Can't find StringEA!"
				return
	
			Func = self.FindUnFunction(StringEA)
	
			if not Func:
				print "Can't find Func!"
				return

			FuncName = idc.GetFunctionName(Func.startEA)
	
			print "Found Data Function:" + FuncName


		
			BundledAssemblyListOffsetsVA = self.FindBundledAssemblyListOffsetsVA(Func.startEA)
			if not BundledAssemblyListOffsetsVA:
				print "Can't find BundledAssemblyListOffsetsVA!"
				return
		else:
			BundledAssemblyListOffsetsVA = ScreenEA()


	
		print("BundledAssemblyListOffsetsVA:0x{:016X}".format(BundledAssemblyListOffsetsVA))

		#StructOffsetList = self.GetStructOffsetList(BundledAssemblyListOffsetsVA)
		BundledAssemblyListOffsetList = self.GetBundledAssemblyListOffsetList(BundledAssemblyListOffsetsVA)
	
		if len(BundledAssemblyListOffsetList) == 0:
			print "Can't find BundledAssemblyListOffsetList!"
			return

		if len(BundledAssemblyListOffsetList) > 2:
			difflen = BundledAssemblyListOffsetList[1] - BundledAssemblyListOffsetList[0]
		else:
			difflen = 0
			return None

		if difflen == 16 or difflen == 32 or difflen == -16 or difflen == -32:
			IsCompressed = True
		else:
			IsCompressed = False

		print "IsCompressed:{}".format(IsCompressed)

		#return None

		#print BundledAssemblyListOffsetList

		BundledAssemblys = []
		BundledAssemblyItemIndex = 0
		for BundledAssemblyListOffset in BundledAssemblyListOffsetList:
			BundledAssemblyItem = self.MakeBundledAssemblyStruct(BundledAssemblyListOffset, IsCompressed)
			BundledAssemblyItem.Index = BundledAssemblyItemIndex
			BundledAssemblys.append(BundledAssemblyItem)
			BundledAssemblyItemIndex += 1

		#print BundledAssemblys

		return BundledAssemblys

	def FindStringEA(self):
		searchstr = str("mkbundle: Error %d decompressing data for %s\n")
		searchstr2 = str("Error %d decompresing data for %s\n")
	
		#Do not use default set up, we'll call setup().
		s = idautils.Strings(default_setup = False)
		# we want C & Unicode strings, and *only* existing strings.
		s.setup(strtypes=Strings.STR_C | Strings.STR_UNICODE, ignore_instructions = True, display_only_existing_strings = True)

		#loop through strings
		for i, v in enumerate(s):                
			if not v:
				#print("Failed to retrieve string at index {}".format(i))
				return -1
			else:
				#print("[{}] ea: {:#x} ; length: {}; type: {}; '{}'".format(i, v.ea,
				#v.length, string_type_map.get(v.type, None), str(v)))
				if str(v) == searchstr or str(v) == searchstr2:
					return v.ea
	
		return -1


	def FindUnFunction(self, StringEA):
		for ref in DataRefsTo(StringEA):
			f = idaapi.get_func(ref)

			if f:
				return f
		return None
	
	def FindBundledAssemblyListOffsetsVA(self, FuncEA):
		for funcitem in FuncItems(FuncEA):
			#print hex(funcitem)
			for dataref in DataRefsFrom(funcitem):
				return dataref
				#print " " + hex(dataref)
		return None
	
	def GetBundledAssemblyListOffsetList(self, DataOffset):



		if self.Is64Bit == True:
			addv = 8
			mf = MakeQword
			vf = Qword
		else:
			mf = MakeDword
			addv = 4
			vf = Dword
	
		AsmListStructListOffset = DataOffset
	
		currentoffset = AsmListStructListOffset



		mf(currentoffset)
		currentvalue = vf(currentoffset)
		currentoffset+=addv


		AsmListStructListOffsetList = []
		AsmListStructListOffsetList.append(currentvalue)
	
		while currentvalue != 0:


			mf(currentoffset)
			currentvalue = vf(currentoffset)
	
			if currentvalue != 0:
				AsmListStructListOffsetList.append(currentvalue)
			currentoffset+=addv
			
		#print len(AsmListStructListOffsetList)
		#for vv in AsmListStructListOffsetList:
			#print hex(vv)
			
		return AsmListStructListOffsetList
	
		
	

	
	def MakeBundledAssemblyStruct(self, FileItemStructOffset, IsCompressed = True):


		if self.Is64Bit == True:
			addv = 8
			mf = MakeQword
			vf = Qword
		else:
			mf = MakeDword
			addv = 4
			vf = Dword
	
		offset = FileItemStructOffset


	
		mf(offset)
		FileNameOffset = vf(offset)
		FileName = idc.GetString(FileNameOffset)
		offset+=addv
	
		mf(offset)
		FileDataOffset = vf(offset)
		offset+=addv
	
		mf(offset)
		FileSize = vf(offset)
		FileSizeOffset = offset
		offset+=addv
	
		if IsCompressed:
			IsME = "N/A"
			mf(offset)
			FileCompressedSize = vf(offset)
			FileCompressedSizeOffset = offset
			offset+=addv
	
			IsGZip = ""
	
			FileDataCompressed = idc.GetManyBytes(FileDataOffset,3)
	
			b1,b2,b3 = struct.unpack('ccc', FileDataCompressed[0:3])
			if b1 == '\x1f' and b2 == '\x8b' and b3 == '\x08':
				IsGZip = "Y"
			else:
				IsGZip = "N"
		else:
			IsME = ""
			IsGZip = "N/A"
			FileDataCompressed = idc.GetManyBytes(FileDataOffset,2)
	
			b1,b2 = struct.unpack('cc', FileDataCompressed[0:2])
			if b1 == '\x4d' and b2 == '\x45':
				IsME = "Y"
			else:
				IsME = "N"
	
		ba = BundledAssembly()
		ba.FileItemStructOffset = FileItemStructOffset
		ba.FileNameOffset = FileNameOffset
		ba.FileName = FileName
		ba.FileDataOffset = FileDataOffset
		ba.FileSize = FileSize
		ba.FileSizeOffset = FileSizeOffset
		if IsCompressed:
			ba.FileCompressedSizeOffset = FileCompressedSizeOffset
			ba.FileCompressedSize = FileCompressedSize
		ba.IsGZip = IsGZip
		ba.IsME = IsME
		if IsCompressed:
			ba.IsCompressed = "Y"
		else:
			ba.IsCompressed = "N"
		#ba.FileDataCompressed = FileDataCompressed

		return ba
		#return {\
		#	"FileItemStructOffset":FileItemStructOffset, \
		#	"FileNameOffset":FileNameOffset,\
		#	"FileName":FileName,\
		#	"FileDataOffset":FileDataOffset,\
		#	"FileSize":FileSize,\
		#	"FileSizeOffset":FileSizeOffset,\
		#	"FileCompressedSizeOffset":FileCompressedSizeOffset,\
		#	"FileCompressedSize":FileCompressedSize,\
		#	"IsGZip":IsGZip,\
		#	"FileDataCompressed":FileDataCompressed\
		#	 }




	#Python语言: Python Cookbook: 比系统自带的更加友好的makedir函数
	#from: http://aspn.activestate.com/ASPN/Cookbook/Python/Recipe/82465
	def _mkdir(self, newdir):
		"""works the way a good mkdir should :)
			- already exists, silently complete
			- regular file in the way, raise an exception
			- parent directory(ies) does not exist, make them as well
		"""
		if os.path.isdir(newdir):
			pass
		elif os.path.isfile(newdir):
			raise OSError("a file with the same name as the desired " \
						  "dir, '%s', already exists." % newdir)
		else:
			head, tail = os.path.split(newdir)
			if head and not os.path.isdir(head):
				_mkdir(head)
			#print "_mkdir %s" % repr(newdir)
			if tail:
				os.mkdir(newdir)

	def DecompressZLib(self, Data,Path):
		
		#compressedstream = StringIO.StringIO(Data)
		data2 = zlib.decompress(Data)
		f = open(Path, 'wb')
		f.write(data2)
		f.close()

	def DecompressGzipTo(self, Data,Path):

		compressedstream = StringIO.StringIO(Data)  
		gziper = gzip.GzipFile(fileobj=compressedstream)    
		data2 = gziper.read()   # 读取解压缩后数据

		f = open(Path, 'wb')
		f.write(data2)
		f.close()

	def DecompressFileTo(self, FileItem,OutputDir):
		
		if FileItem.IsME == "Y":
			extname = ".ME"
		else:
			extname = ""

		newpath = '{}\\{}{}'.format(OutputDir, FileItem.FileName, extname)

		if FileItem.IsCompressed == "Y":
			FileDataCompressed = idc.GetManyBytes(FileItem.FileDataOffset,FileItem.FileCompressedSize)
			if FileItem.IsGZip == "Y":
				self.DecompressGzipTo(FileDataCompressed,newpath)
			else:
				self.DecompressZLib(FileDataCompressed,newpath)
		else:
			FileData = idc.GetManyBytes(FileItem.FileDataOffset,FileItem.FileSize)
			f = open(newpath, 'wb')
			f.write(FileData)
			f.close()
			pass

	def CompressGzipToData(self, data):
		buf = StringIO.StringIO() 
		f = gzip.GzipFile(mode='wb',compresslevel=9,fileobj=buf)
		try:
			f.write(data)
		finally:
			f.close()
		compresseddata = buf.getvalue()

		return compresseddata

	def CompressZLibToData(self, data):
		compressobj = zlib.compressobj(zlib.Z_BEST_COMPRESSION, zlib.DEFLATED, zlib.MAX_WBITS, 8 ,zlib.Z_DEFAULT_STRATEGY)
		data2 = compressobj.compress(data)
		data2 += compressobj.flush()
		return data2

	def ReplaceFile(self, FileItem,BundleFilePath,NewFilePath):

		print "Start replace file: {}".format(NewFilePath)

		if not os.path.exists(BundleFilePath):
			print "BundleFilePath error!"
			return


		if not os.path.isfile(NewFilePath):
			print "NewFilePath error!"
			return

		f = open(NewFilePath, 'rb')
		NewFileData = f.read()
		f.close()


		if FileItem.IsCompressed == "Y":
			if FileItem.IsGZip == "Y":
				compresseddata = self.CompressGzipToData(NewFileData)
			else:
				compresseddata = self.CompressZLibToData(NewFileData)

			sizediff = FileItem.FileCompressedSize - len(compresseddata)
			print "FileCompressedSize - compresseddata = 0x{:016X} - 0x{:016X} = 0x{:016X}".format(FileItem.FileCompressedSize,len(compresseddata),sizediff)

			if sizediff < 0:
				print "FileCompressedSize < compresseddata,can't replace!"
				return
		else:
			compresseddata = NewFileData
			sizediff = FileItem.FileSize - len(compresseddata)
			print "FileSize - compresseddata = 0x{:016X} - 0x{:016X} = 0x{:016X}".format(FileItem.FileSize,len(compresseddata),sizediff)

			if sizediff < 0:
				print "FileSize < compresseddata,can't replace!"
				return




		FileSizeOffset = idaapi.get_fileregion_offset(FileItem.FileSizeOffset)

		if FileItem.IsCompressed == "Y":
			FileCompressedSizeOffset = idaapi.get_fileregion_offset(FileItem.FileCompressedSizeOffset)

		FileDataOffset = idaapi.get_fileregion_offset(FileItem.FileDataOffset)
		#ea = idaapi.get_fileregion_ea(offset)

		NewFileDataSize = len(NewFileData)
		if FileItem.IsCompressed == "Y":
			NewCompressedDataSize = len(compresseddata)
			print "FileSizeOffset = 0x{:016X},FileCompressedSizeOffset = 0x{:016X},FileDataOffset = 0x{:016X}".format(FileSizeOffset,FileCompressedSizeOffset,FileDataOffset)
		else:
			print "FileSizeOffset = 0x{:016X},FileDataOffset = 0x{:016X}".format(FileSizeOffset,FileDataOffset)
		

		input_file_dir = os.path.dirname(BundleFilePath)
		input_file_fullname = os.path.basename(BundleFilePath) 
		input_file_name,input_file_extname = os.path.splitext(input_file_fullname)
		#分离扩展名：os.path.splitext(r"c:\python\hello.py") --> ("c:\\python\\hello",
		#".py")


		output_file_fullname = '{}_{:%Y%m%d%H%M%S%f}{}'.format(input_file_name, datetime.now(),input_file_extname)
		output_file_fullpath = os.path.join(input_file_dir,output_file_fullname)


		#shutil.copy(BundleFilePath, output_file_fullpath)

		print "new BundleFilePath path:{}".format(output_file_fullpath)



		fp = open(BundleFilePath,"rb")
		data = fp.read() #读出文件内容
		
		fp.close()


		if self.Is64Bit == True:
			NewFileDataSizeData = struct.pack("q",NewFileDataSize)
			if FileItem.IsCompressed == "Y":
				NewCompressedDataSizeData = struct.pack("q",NewCompressedDataSize)
		else:
			NewFileDataSizeData = struct.pack("l",NewFileDataSize)
			if FileItem.IsCompressed == "Y":
				NewCompressedDataSizeData = struct.pack("l",NewCompressedDataSize)

		
		
		#data 不可更改元素，是固定的,必须转成可对元素操作的list
		data = list(data)


		#try:
		#	data[0] = 'a'
		#	data[1] = 'a'
		#	data[2] = 'a'
		#except Exception,e:
		#	print Exception,":",e


		#range(m, n)这里，range()函数产生的是一个从 m至n-1的整数列表


		#update FileSize
		for i in range(0, len(NewFileDataSizeData)):
			data[FileSizeOffset + i] = NewFileDataSizeData[i]

		##update FileCompressedSize
		if FileItem.IsCompressed == "Y":
			for i in range(0, len(NewCompressedDataSizeData)):
				data[FileCompressedSizeOffset + i] = NewCompressedDataSizeData[i]


		##clear FileData
		if FileItem.IsCompressed == "Y":
			for i in range(0, FileItem.FileCompressedSize):
				data[FileDataOffset + i] = chr(0x0)
				pass
		else:
			for i in range(0, FileItem.FileSize):
				data[FileDataOffset + i] = chr(0x0)
				pass

		##update FileData
		for i in range(0, len(compresseddata)):
			data[FileDataOffset + i] = compresseddata[i]
			pass

		fp2 = open(output_file_fullpath,"wb")
		#把data的list转为str并写入文件
		fp2.write(''.join(data))#重写
		fp2.close()


		print "replace ok!"

class ReplaceFileForm(Form):
	def __init__(self,bundleFile,impFile):
		Form.__init__(self,
r"""BUTTON YES* 替换
BUTTON CANCEL 取消
请选择文件（文件压缩后数据大小必须小于替换前压缩后数据大小）

{FormChangeCb}
<##选择被打包的文件:{bundleFile}>
<##选择修改后的文件:{impFile}>

""".decode('utf-8').encode(sys.getfilesystemencoding()), {  'bundleFile': Form.FileInput(open=True,value=bundleFile),
		'impFile': Form.FileInput(open=True,value=impFile),

		'FormChangeCb': Form.FormChangeCb(self.OnFormChange),
		})

		self.Compile()

	def OnFormChange(self, fid):
		# Form initialization
		if fid == -1:
			self.SetFocusedField(self.bundleFile)
			self.EnableField(self.bundleFile, True)
			self.EnableField(self.impFile, True)
		
		# Form OK pressed
		elif fid == -2:
		    pass
		elif fid == self.bundleFile.id:
			pass
		return 1

class SaveItemsToDirForm(Form):
	def __init__(self,defaultpath):
		Form.__init__(self,
r"""BUTTON YES* 保存
BUTTON CANCEL 取消
请选择输出目录

{FormChangeCb}

<##输出目录:{impFile}>
""".decode('utf-8').encode(sys.getfilesystemencoding()), {
		'impFile': Form.DirInput(value=defaultpath),

		'FormChangeCb': Form.FormChangeCb(self.OnFormChange),
		})

		self.Compile()

	def OnFormChange(self, fid):
		# Form initialization
		if fid == -1:
			self.SetFocusedField(self.impFile)
			self.EnableField(self.impFile, True)
		
		# Form OK pressed
		elif fid == -2:
			pass
		return 1

class BundledAssemblyManagerView(Choose2):
	def __init__(self):
		Choose2.__init__(self,
			"Bundled Assembly Manager",
			[
				["Index",                      6 | Choose2.CHCOL_DEC], 
				["FileItemStructOffset",      18 | Choose2.CHCOL_HEX], 
				["FileNameOffset",            18 | Choose2.CHCOL_HEX], 
				["FileDataOffset",            18 | Choose2.CHCOL_HEX], 
				["FileSize",                  18 | Choose2.CHCOL_HEX], 
				["FileSizeOffset",            18 | Choose2.CHCOL_HEX], 
				["FileCompressedSizeOffset",  18 | Choose2.CHCOL_HEX], 
				["FileCompressedSize",        18 | Choose2.CHCOL_HEX], 
				["IsCompressed",              4  | Choose2.CHCOL_PLAIN], 
				["IsGZip",                    4  | Choose2.CHCOL_PLAIN], 
				["IsME",                      4  | Choose2.CHCOL_PLAIN], 
				["FileName",                  18 | Choose2.CHCOL_PLAIN]
			])
		#self.popup_names = ["Insert", "Delete", "Edit", "Refresh"]

		self.icon = 47

		self.tool = None
		
		self.items = []
		self.items_data = []

		# Command callbacks
		self.cmd_Items_SaveAs = None
		self.cmd_Item_SaveAs = None
		self.cmd_Item_ReplaceBy = None

	def show(self):

		try:
			# Initialize/Refresh the view
			if self.refreshitems():
				if self.Show() < 0: return False
			#self.Refresh()
		except:
			traceback.print_exc()
		

		# Attempt to open the view
		



		if self.cmd_Items_SaveAs == None:
			self.cmd_Items_SaveAs = self.AddCommand("导出全部文件...".decode('utf-8').encode(sys.getfilesystemencoding()), flags = idaapi.CHOOSER_POPUP_MENU | idaapi.CHOOSER_NO_SELECTION, icon=139)
		
		if self.cmd_Item_SaveAs == None:
			self.cmd_Item_SaveAs = self.AddCommand("导出文件...".decode('utf-8').encode(sys.getfilesystemencoding()), flags = idaapi.CHOOSER_POPUP_MENU, icon=139)
		
		if self.cmd_Item_ReplaceBy == None:
			self.cmd_Item_ReplaceBy = self.AddCommand("替换文件...".decode('utf-8').encode(sys.getfilesystemencoding()), flags = idaapi.CHOOSER_POPUP_MENU, icon=139)

		return True

	def refreshitems(self):
		#print "refreshitems"
		self.items_data = []
		self.items = []
		try:

			#-1:cancel,0-no,1-ok
			UseScreenEAInt = idc.AskYN(1,"是否自动获取数据位置?(否则使用ScreenEA)".decode('utf-8').encode(sys.getfilesystemencoding()))

			if UseScreenEAInt == -1:
				UseScreenEAInt = 1

			if UseScreenEAInt == 1:
				UseScreenEA = False
			else:
				UseScreenEA = True

			print "UseScreenEA:{}".format(UseScreenEA)


			self.tool = MKBundleTool()
			asms = self.tool.GetBundledAssemblyList(UseScreenEA)
			if not asms:
				return False
			for BundledAssemblyItem in asms:
				#print BundledAssemblyItem
			
				#print("FileItemStructOffset:{:016X} FileNameOffset:{:016X}
				#FileDataOffset:{:016X} FileSize:{:016X} FileCompressedSize:{:016X}
				#IsGZip:{} FileName:{}"\
				#.format( \
				#BundledAssemblyItem.FileItemStructOffset , \
				#BundledAssemblyItem.FileNameOffset,\
				#BundledAssemblyItem.FileDataOffset,\
				#BundledAssemblyItem.FileSize,\
				#BundledAssemblyItem.FileCompressedSize,\
				#BundledAssemblyItem.IsGZip,\
				#BundledAssemblyItem.FileName))


				if  self.tool.Is64Bit:
					fstr = "0x%016X"
				else:
					fstr = "0x%08X"


				self.items_data.append(BundledAssemblyItem)
				self.items.append(["%d" % BundledAssemblyItem.Index,
									fstr % BundledAssemblyItem.FileItemStructOffset,
									fstr % BundledAssemblyItem.FileNameOffset,
									fstr % BundledAssemblyItem.FileDataOffset,
									fstr % BundledAssemblyItem.FileSize,
									fstr % BundledAssemblyItem.FileSizeOffset,
									fstr % BundledAssemblyItem.FileCompressedSizeOffset,
									fstr % BundledAssemblyItem.FileCompressedSize,
									BundledAssemblyItem.IsCompressed,
									BundledAssemblyItem.IsGZip,
									BundledAssemblyItem.IsME,
									BundledAssemblyItem.FileName])
			return True

		except:
			traceback.print_exc()
			return False

	def OnCommand(self, n, cmd_id):


		if self.tool == None:
			return 1;

		if cmd_id == self.cmd_Items_SaveAs:

			OutputDir = '{}_{:%Y%m%d%H%M%S%f}'.format(GetInputFilePath(), datetime.now())

			f = SaveItemsToDirForm(OutputDir)

			# Execute the form
			ok = f.Execute()
			if ok == 1:
				try:
					imp_file = f.impFile.value
					self.tool._mkdir(imp_file)

					for item in self.items_data:
						self.tool.DecompressFileTo(item,OutputDir)
				except:
					traceback.print_exc()

			# Dispose the form
			f.Free()
		elif cmd_id == self.cmd_Item_SaveAs:

			item = self.items_data[n]

			OutputDir = '{}_{:%Y%m%d%H%M%S%f}'.format(GetInputFilePath(), datetime.now())

			f = SaveItemsToDirForm(OutputDir)

			# Execute the form
			ok = f.Execute()
			if ok == 1:
				try:
					imp_file = f.impFile.value
					self.tool._mkdir(imp_file)
					self.tool.DecompressFileTo(item,OutputDir)
				except:   
					traceback.print_exc()
			# Dispose the form
			f.Free()
		elif cmd_id == self.cmd_Item_ReplaceBy:
			item = self.items_data[n]

			f = ReplaceFileForm(GetInputFilePath(),item.FileName)

			# Execute the form
			ok = f.Execute()
			if ok == 1:
				try:   
					self.tool.ReplaceFile(item,f.bundleFile.value,f.impFile.value)
				except:
					traceback.print_exc()
					
			f.Free()
			pass

		return 1

	def OnClose(self):
		self.cmd_Items_SaveAs = None
		self.cmd_Item_SaveAs = None
		self.cmd_Item_ReplaceBy = None

	def OnSelectLine(self, n):
		idaapi.jumpto(self.items_data[n].FileItemStructOffset)
		pass

	def OnGetLine(self, n):
		return self.items[n]

	def OnGetIcon(self, n):
		# Empty list
		if not len(self.items) > 0:
		    return -1

		#return -1
		return 137


	def OnGetSize(self):
		return len(self.items)
	
	def OnRefresh(self, n):
		#print "OnRefresh"
		self.refreshitems()
		return n

	def OnActivate(self):
		#print "OnActivate"
		self.refreshitems()

class MKBundleManager():
	""" Class that manages GUI forms and MKBundleManager methods of the plugin. """
	def __init__(self): 
		
		self.addmenu_item_ctxs = list()
		self.bundledAssemblyManagerView = None
		#self.bundledAssemblyManagerView = BundledAssemblyManagerView()

	#--------------------------------------------------------------------------
	# Menu Items
	#--------------------------------------------------------------------------
	def add_menu_item_helper(self, menupath, name, hotkey, flags, pyfunc, args):
	
		# add menu item and report on errors
		addmenu_item_ctx = idaapi.add_menu_item(menupath, name, hotkey, flags, pyfunc, args)
		if addmenu_item_ctx is None:
			return 1
		else:
			self.addmenu_item_ctxs.append(addmenu_item_ctx)
			return 0
	
	def add_menu_items(self):
	
		if self.add_menu_item_helper("View/Open subviews/Problems", "Bundled Assembly Manager", "", 1, self.Show_BundledAssemblyManagerView, None): return 1
		return 0
	
	def del_menu_items(self):
		for addmenu_item_ctx in self.addmenu_item_ctxs:
			idaapi.del_menu_item(addmenu_item_ctx)

	#--------------------------------------------------------------------------
	# View Callbacks
	#--------------------------------------------------------------------------
	
	# BundledAssemblyManagerView View
	def Show_BundledAssemblyManagerView(self):

		try:
			if not self.bundledAssemblyManagerView == None:
				self.bundledAssemblyManagerView.Close()
				self.bundledAssemblyManagerView = None

			self.bundledAssemblyManagerView = BundledAssemblyManagerView()
			self.bundledAssemblyManagerView.show()
		except:
			traceback.print_exc()
#--------------------------------------------------------------------------
# Plugin
#--------------------------------------------------------------------------
class MKBundleManager_t(plugin_t):

	flags = idaapi.PLUGIN_UNL
	comment = "MK Bundle Manager."
	help = "MK Bundle Manager.."
	wanted_name = "MK Bundle Manager"
	wanted_hotkey = ""
	
	def init(self):  
		global MKBundleManagerInstance
		
		# Check if already initialized
		if not 'MKBundleManagerInstance' in globals():
		
			MKBundleManagerInstance = MKBundleManager()
			if MKBundleManagerInstance.add_menu_items():
				print "Failed to initialize MK Bundle Manager."
				MKBundleManagerInstance.del_menu_items()
				del MKBundleManagerInstance
				return idaapi.PLUGIN_SKIP
			else:  
				print("Initialized MKBundleManager v%s (c) BinSys <binsys@163.com>" % MKBundleManager_VERSION)
			
		return idaapi.PLUGIN_KEEP
	
	def run(self, arg):
		global MKBundleManagerInstance
		idc.Wait()
		MKBundleManagerInstance.Show_BundledAssemblyManagerView()
	
	def term(self):
		pass

def PLUGIN_ENTRY():
	return MKBundleManager_t()

#--------------------------------------------------------------------------
# Script / Testing
#--------------------------------------------------------------------------
def MKBundleManager_main():
	global MKBundleManagerInstance
	
	if 'MKBundleManagerInstance' in globals():
		MKBundleManagerInstance.del_menu_items()
		del MKBundleManagerInstance
	
	MKBundleManagerInstance = MKBundleManager()
	MKBundleManagerInstance.add_menu_items()
	MKBundleManagerInstance.Show_BundledAssemblyManagerView()

if __name__ == '__main__':
	try:
		#print("Initialized MKBundleManager  %s (c) BinSys <binsys@163.com>" % MKBundleManager_VERSION)
		#MKBundleManager_main() #for Developer only
		pass
	except:
		traceback.print_exc()
	pass