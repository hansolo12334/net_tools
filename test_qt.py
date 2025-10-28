import sys
import os
sys.path.append(os.path.dirname(__file__))


from PyQt5.QtWidgets import *
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPixmap,QImage

# sys.path.append(os.path.join(os.path.dirname(__file__),'utils'))
from utils.NetData import NetDataRecorder,ExeData

from PIL import Image

class Table(QWidget):
    def __init__(self):
        super(Table, self).__init__()
        
        self.TableWidget = QTableWidget()
        self.layout=QHBoxLayout()
        self.netdata_recorder =NetDataRecorder()
        
        self.current_exe_list= {}
        
        self.initUI()
        
        self.init_conection()
    
    def init_conection(self):
        # 连接信号和槽的方法，如果有其他信号连接可以在这里添加
        self.netdata_recorder.exe_data_signal.connect(self.add_data)  # 连接网络
        
    def initUI(self):
        self.setWindowTitle("NetWorkMonitor")
        self.resize(1400,800)
        

        #实现的效果是一样的，四行三列，所以要灵活运用函数，这里只是示范一下如何单独设置行列
        self.TableWidget=QTableWidget(0,6)

        # TableWidget = QTableWidget()
        # TableWidget.setRowCount(4)
        # TableWidget.setColumnCount(3)



        #设置水平方向的表头标签与垂直方向上的表头标签，注意必须在初始化行列之后进行，否则，没有效果
        self.TableWidget.setHorizontalHeaderLabels(['应用程序名称','应用程序路径','接收字节数','发送字节数','接收速度','发送速度'])
        #Todo 优化1 设置垂直方向的表头标签
        #TableWidget.setVerticalHeaderLabels(['行1', '行2', '行3', '行4'])

        #TODO 优化 2 设置水平方向表格为自适应的伸缩模式
        # TableWidget.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        # TableWidget.verticalHeader().setSectionResizeMode(QHeaderView.Stretch)

        self.TableWidget.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOn)
        self.TableWidget.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOn)
        #TODO 优化3 将表格变为禁止编辑
        #TableWidget.setEditTriggers(QAbstractItemView.NoEditTriggers)

        #TODO 优化 4 设置表格整行选中
        #TableWidget.setSelectionBehavior(QAbstractItemView.SelectRows)

        #TODO 优化 5 将行与列的高度设置为所显示的内容的宽度高度匹配
        #QTableWidget.resizeColumnsToContents(TableWidget)
        #QTableWidget.resizeRowsToContents(TableWidget)

        #TODO 优化 6 表格头的显示与隐藏
        #TableWidget.verticalHeader().setVisible(False)
        #TableWidget.horizontalHeader().setVisible(False)

        #TOdo 优化7 在单元格内放置控件
        # comBox=QComboBox()
        # comBox.addItems(['男','女'])
        # comBox.addItem('未知')
        # comBox.setStyleSheet('QComboBox{margin:3px}')
        # TableWidget.setCellWidget(0,1,comBox)
        #
        # searchBtn=QPushButton('修改')
        # searchBtn.setDown(True)
        # searchBtn.setStyleSheet('QPushButton{margin:3px}')
        # TableWidget.setCellWidget(0,2,searchBtn)


        #添加数据
        # newItem=QTableWidgetItem('张三')
        # self.TableWidget.setItem(0,0,newItem)

        # newItem=QTableWidgetItem('男')
        # self.TableWidget.setItem(0,1,newItem)

        # newItem=QTableWidgetItem('160')
        # self.TableWidget.setItem(0,2,newItem)

        self.layout.addWidget(self.TableWidget)

        self.setLayout(self.layout)
        
        self.netdata_recorder.start()  # 启动网络数据记录线程
        
    def closeEvent(self, event):
        """窗口关闭事件处理"""
        self.netdata_recorder.stop()  # 停止网络数据记录线程
        event.accept()  # 接受关闭事件

    
    def extract_exe_thumbnail(self, exe_icon : Image)-> QPixmap:
        """
        从ExeData对象中提取图标并转换为QPixmap。
        参数：
            exe_icon (PIL.Image): ExeData对象中的图标
        返回：
            QPixmap: 转换后的QPixmap对象
        """
        if exe_icon is None:
            return QPixmap()
        
        if exe_icon.mode == 'RGBA':
            exe_icon = exe_icon.convert('RGBA')
            data = exe_icon.tobytes('raw', 'RGBA')
            width, height = exe_icon.size
            qimage = QImage(data, width, height, QImage.Format_RGBA8888)
        else:
            exe_icon = exe_icon.convert('RGB')
            data = exe_icon.tobytes('raw', 'RGB')
            width, height = exe_icon.size
            qimage = QImage(data, width, height, QImage.Format_RGB888)
        # 转换为 QPixmap
        pixmap = QPixmap.fromImage(qimage)
        # pixmap = pixmap.scaled(self.TableWidget.rowHeight(0), self.TableWidget.rowHeight(0), Qt.KeepAspectRatio)  # 缩放图像
        return pixmap
        
    def add_data(self,exe_data: ExeData):
        
        if exe_data.name in self.current_exe_list:
            # 如果应用程序已经存在，更新数据
            # row = self.current_exe_list[exe_data.name]
            # self.TableWidget.setItem(row, 2, QTableWidgetItem(str(exe_data.recv_bytes)))
            # self.TableWidget.setItem(row, 3, QTableWidgetItem(str(exe_data.send_bytes)))
            # self.TableWidget.setItem(row, 4, QTableWidgetItem(str(exe_data.recv_speed)))
            # self.TableWidget.setItem(row, 5, QTableWidgetItem(str(exe_data.send_speed)))
            self.update_data(exe_data)
            return
        
        # 如果应用程序不存在，添加新行
        row = self.TableWidget.rowCount()
        
        self.TableWidget.setRowCount(row + 1)
        
        imgLabel = QLabel()
        exe_pixmap=self.extract_exe_thumbnail(exe_data.exe_icon)
        if exe_data.exe_icon:
            imgLabel.setPixmap(exe_pixmap)
            imgLabel.setAlignment(Qt.AlignCenter)  # 居中对齐
            imgLabel.setAttribute(Qt.WA_TranslucentBackground)
            
        text_label = QLabel(exe_data.name)    
        exe_name=QLabel()
        exe_name.setAttribute(Qt.WA_TranslucentBackground)
        exe_name_layout=QHBoxLayout()
        exe_name_layout.setContentsMargins(0, 0, 0, 0)
        exe_name_layout.addWidget(imgLabel)
        exe_name_layout.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)  # 左对齐并垂直居中
        exe_name_layout.addWidget(text_label)
        exe_name.setLayout(exe_name_layout)
        
        self.TableWidget.setCellWidget(row, 0, exe_name)  # 设置图标为第一列的单元格小部件
        
        
        if exe_pixmap.height() >0:
            self.TableWidget.setRowHeight(row, exe_pixmap.height())
        
        self.TableWidget.setItem(row, 1, QTableWidgetItem(exe_data.path))
        self.TableWidget.setItem(row, 2, QTableWidgetItem(str(exe_data.total_download_bytes)))
        self.TableWidget.setItem(row, 3, QTableWidgetItem(str(exe_data.total_upload_bytes)))
        self.TableWidget.setItem(row, 4, QTableWidgetItem(str(exe_data.recv_speed)))
        self.TableWidget.setItem(row, 5, QTableWidgetItem(str(exe_data.send_speed)))
        
        self.current_exe_list[exe_data.name] = exe_data
       
    
    def update_data(self,exe_data: ExeData):
        
        for row in range(self.TableWidget.rowCount()):
            item = self.TableWidget.item(row, 1)
            if item and item.text() == exe_data.path:
                # 找到对应的行，更新数据
                self.TableWidget.setItem(row, 2, QTableWidgetItem(str(exe_data.total_download_bytes)))
                self.TableWidget.setItem(row, 3, QTableWidgetItem(str(exe_data.total_upload_bytes)))
                self.TableWidget.setItem(row, 4, QTableWidgetItem(str(exe_data.recv_speed)))
                self.TableWidget.setItem(row, 5, QTableWidgetItem(str(exe_data.send_speed)))
                break
    
    
        
if __name__ == '__main__':
    app=QApplication(sys.argv)
    win=Table()

    win.show()
    sys.exit(app.exec_())