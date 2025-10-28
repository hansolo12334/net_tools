import sys
import os
sys.path.append(os.path.dirname(__file__))


from PyQt5.QtWidgets import *
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPixmap,QImage


from utils.NetData_useDll import NetDataRecorder,ExeData

from PIL import Image


class SPEED_UNINT:
    """Docstring for MyEnum."""
    MB_per = " MB/s"
    KB_per = " Kb/s"
    MB= " MB"
    KB= " Kb"
                 
             
class Table(QMainWindow):
    def __init__(self):
        super(Table, self).__init__()
        
        self.TableWidget = QTableWidget()
        self.layout=QHBoxLayout()
        self.netdata_recorder =NetDataRecorder()
        
        self.current_exe_list= {str: ExeData}  # 存储当前的ExeData对象，key为应用程序名称
        
        self.speed_unit = SPEED_UNINT
        
        
        
        
        self.initUI()
        
        self.init_conection()
    
    def init_conection(self):
        # 连接信号和槽的方法，如果有其他信号连接可以在这里添加
        self.netdata_recorder.exe_data_signal.connect(self.add_data)  # 连接网络
        
    def initUI(self):
        self.setWindowTitle("NetWorkMonitor")
        self.resize(1400,800)
        

        #实现的效果是一样的，四行三列，所以要灵活运用函数，这里只是示范一下如何单独设置行列
        self.TableWidget=QTableWidget(0,24)

        # TableWidget = QTableWidget()
        # TableWidget.setRowCount(4)
        # TableWidget.setColumnCount(3)



        #设置水平方向的表头标签与垂直方向上的表头标签，注意必须在初始化行列之后进行，否则，没有效果
        self.TableWidget.setHorizontalHeaderLabels(['应用程序名称','应用程序路径',
                                                    '接收字节数','发送字节数',
                                                    '接收速度','发送速度',
                                                    '已接收包数','已发送包数',
                                                    'IPv4接收字节数','IPv4发送字节数',
                                                    'IPv6接收字节数','IPv6发送字节数',
                                                    '接收+发送字节数','接收+发送包数',
                                                    '最大接收速度','最大发送速度',
                                                    '平均接收速度','平均发送速度',
                                                    '最先活动时间','最后活动时间',
                                                    '产品名称','产品版本',
                                                    '文件描述', '公司名称'])
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

 
        self.setCentralWidget(self.TableWidget)  # 设置中心小部件为TableWidget
    
        #添加菜单栏
        self.addMamuBar()
        
        
        self.netdata_recorder.start()  # 启动网络数据记录线程
    
    
    
    # def sort_event(self, checked : bool, current_action: QAction):
    #         """排序事件处理函数"""
            
    #         if current_action.isChecked() and not checked:
    #             current_action.setChecked(False)
    #             print(f"取消选中排序方式: {current_action.text()}")
    #             return
            
    #         if checked:
                
    #             col_index = self.sort_method_menu.actions().index(current_action)
                
                
    #             if col_index ==1 or col_index==0:
                    
    #                 #清除临时数据（可选）
    #                 for row in range(self.TableWidget.rowCount()):
    #                     item = self.TableWidget.item(row, col_index)
    #                     if item:
    #                         item.setData(Qt.UserRole, None)
                            
    #                 # 临时存储排序键（不区分大小写）
    #                 for row in range(self.TableWidget.rowCount()):
    #                     item = self.TableWidget.item(row, col_index)
    #                     if item:
    #                         path = item.text().lower()  # 转为小写，避免大小写影响排序
    #                         print(f"存储排序键: {path}")
    #                         item.setData(Qt.UserRole, path)  # 存储排序键

    #                 print(f"当前选中排序方式: {current_action.text()}, 列索引: {col_index}")
    #                 self.TableWidget.sortItems(col_index, Qt.DescendingOrder)  # 强制降序

                    
                    
                            
    #             else:
    #                 print(f"当前选中排序方式: {current_action.text()}, 列索引: {col_index}")
    #                 self.TableWidget.sortItems(col_index, Qt.AscendingOrder)
                
    #             # 确保只有一个action被选中
    #             for action in self.sort_method_menu.actions():
    #                 if action != current_action:
    #                     action.setChecked(False)


    def create_exe_name_widget(self, name, row):
        """创建第一列的 QWidget（图标 + 文本）"""
        # 创建 QLabel 用于显示进程名称
        text_label = QLabel(name)
        
        # 获取进程图标
        imgLabel = QLabel()
   
        exe_pixmap=self.extract_exe_thumbnail(self.current_exe_list[name].exe_icon )
        imgLabel.setPixmap(exe_pixmap)
        
        # 创建布局
        exe_name = QLabel()
        exe_name.setAttribute(Qt.WA_TranslucentBackground)
        exe_name_layout = QHBoxLayout()
        exe_name_layout.setContentsMargins(0, 0, 0, 0)
        exe_name_layout.addWidget(imgLabel)
        exe_name_layout.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        exe_name_layout.addWidget(text_label)
        exe_name.setLayout(exe_name_layout)
        
        if exe_pixmap.height() >0:
            self.TableWidget.setRowHeight(row, exe_pixmap.height())
            
        return exe_name

    def sort_event(self, checked, action):
        if not checked:
            return
        column_name = action.text()
        is_numeric = column_name in [
            '接收字节数', '发送字节数', '接收速度', '发送速度',
            '已接收包数', '已发送包数', 'IPv4接收字节数', 'IPv4发送字节数',
            'IPv6接收字节数', 'IPv6发送字节数', '接收+发送字节数', '接收+发送包数',
            '最大接收速度', '最大发送速度', '平均接收速度', '平均发送速度'
        ]

        # 取消其他选中
        for a in self.sort_method_menu.actions():
            if a != action:
                a.setChecked(False)

        # 收集行数据
        rows = []
        headers = [self.TableWidget.horizontalHeaderItem(i).text() for i in range(self.TableWidget.columnCount())]
        for row in range(self.TableWidget.rowCount()):
            row_data = {}
            for col, header in enumerate(headers):
                if col == 0:  # 第一列是 QWidget
                    widget = self.TableWidget.cellWidget(row, 0)
                    if widget:
                        # 查找布局中的第二个 QLabel（文本）
                        layout = widget.layout()
                        text_label = layout.itemAt(1).widget() if layout.count() > 1 else None
                        row_data[header] = text_label.text() if text_label else " "
                        # 存储路径用于重新生成图标
                        row_data["exe_path"] = self.TableWidget.item(row, 1).text() if self.TableWidget.item(row, 1) else " "
                    else:
                        row_data[header] = " "
                        row_data["exe_path"] = " "
                else:
                    item = self.TableWidget.item(row, col)
                    row_data[header] = item.text() if item and item.text() else " "
            rows.append(row_data)

        # 排序
        if is_numeric:
            rows.sort(key=lambda x: float(x[column_name].split(' ')[0]) if x[column_name] != " " else 0.0, reverse=True)
        else:
            rows.sort(key=lambda x: x[column_name].lower() if x[column_name] != " " else "")

        # 更新表格
        self.TableWidget.setRowCount(0)
        self.TableWidget.setRowCount(len(rows))
        for row, data in enumerate(rows):
            for col, header in enumerate(headers):
                if col == 0:
                    # 重新创建第一列的 QWidget
                    exe_name_widget = self.create_exe_name_widget(data[header], row)
                    self.TableWidget.setCellWidget(row, 0, exe_name_widget)
                else:
                    item = QTableWidgetItem(data[header])
                    self.TableWidget.setItem(row, col, item)
        
            
    def addMamuBar(self):
        '''
        添加菜单栏
        '''
        self.manubar = QMenuBar(self)
        self.setMenuBar(self.manubar)

        self.file_menu = self.manubar.addMenu('文件')
        self.view_menu = self.manubar.addMenu('查看')
        self.option_menu = self.manubar.addMenu('选项')
        
        
        #文件菜单
        self.file_menu.addAction('退出', self.close)  # 添加退出菜单项
        
        
        #查看菜单
        self.sort_method_menu = QMenu()
        self.sort_method_menu.setTitle('排序方式')
  
        
        self.sort_method_menu.addActions([QAction("应用程序名称", self), QAction("应用程序路径", self),
                                          QAction("接收字节数", self), QAction("发送字节数", self),
                                          QAction("接收速度", self), QAction("发送速度", self),
                                          QAction("已接收包数", self), QAction("已发送包数", self),
                                          QAction("IPv4接收字节数", self), QAction("IPv4发送字节数", self)])
        
        
        
            
            # for action in self.sort_method_menu.actions():
            #     action.setChecked(action == current_action)
                
            # if checked:
            #     self.TableWidget.sortByColumn(self.sort_method_menu.actions().index(current_action), Qt.AscendingOrder)
            
            # for action in self.sort_method_menu.actions():
            #     if action != current_action:
            #         action.setChecked(False)
                
        for action in self.sort_method_menu.actions():
            action.setCheckable(True)
            
            action.triggered.connect(lambda checked, a=action: self.sort_event(checked, a))

        
            
        #选项菜单
        self.speed_unit_menu = QMenu()
        self.speed_unit_menu.setTitle('速度单位')
        
        self.kb_speed_action = QAction('Kb/s', self)
        self.mb_speed_action = QAction('MB/s', self)
        self.kb_speed_action.setCheckable(True)
        self.mb_speed_action.setCheckable(True)
        
        self.speed_unit_menu.addAction(self.kb_speed_action)
        self.speed_unit_menu.addAction(self.mb_speed_action)
        
        
        
        
        self.view_menu.addMenu(self.sort_method_menu)
        self.option_menu.addMenu(self.speed_unit_menu)
        
    
    
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
        exe_data.get_exe_info_win32com() #只在添加时计算一次 固定信息
        
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
        recv_bytes = round(exe_data.recv_bytes, 2)
        send_bytes = round(exe_data.send_bytes, 2)      
        recv_speed = round(exe_data.recv_speed, 2)
        send_speed = round(exe_data.send_speed, 2)
        ipv4_recv_bytes = round(exe_data.ipv4_recv_bytes, 2)
        ipv4_send_bytes = round(exe_data.ipv4_send_bytes, 2)
        ipv6_recv_bytes = round(exe_data.ipv6_recv_bytes, 2)
        ipv6_send_bytes = round(exe_data.ipv6_send_bytes, 2)
                
        self.TableWidget.setItem(row, 2, QTableWidgetItem(str(recv_bytes)+self.speed_unit.MB))
        self.TableWidget.setItem(row, 3, QTableWidgetItem(str(send_bytes)+self.speed_unit.MB))
        self.TableWidget.setItem(row, 4, QTableWidgetItem(str(recv_speed)+self.speed_unit.MB_per))
        self.TableWidget.setItem(row, 5, QTableWidgetItem(str(send_speed)+self.speed_unit.MB_per))
        
        self.TableWidget.setItem(row, 6, QTableWidgetItem(str(exe_data.recv_packets)))
        self.TableWidget.setItem(row, 7, QTableWidgetItem(str(exe_data.send_packets)))
        
        self.TableWidget.setItem(row, 8, QTableWidgetItem(str(ipv4_recv_bytes)+ self.speed_unit.MB))
        self.TableWidget.setItem(row, 9, QTableWidgetItem(str(ipv4_send_bytes)+ self.speed_unit.MB))
        self.TableWidget.setItem(row, 10, QTableWidgetItem(str(ipv6_recv_bytes)+ self.speed_unit.MB))
        self.TableWidget.setItem(row, 11, QTableWidgetItem(str(ipv6_send_bytes)+ self.speed_unit.MB))
        
        self.TableWidget.setItem(row,20,QTableWidgetItem(exe_data.product_name))
        self.TableWidget.setItem(row,21,QTableWidgetItem(exe_data.product_version))
        self.TableWidget.setItem(row,22,QTableWidgetItem(exe_data.file_description))        
        self.TableWidget.setItem(row,23,QTableWidgetItem(exe_data.company_name))
        
        self.current_exe_list[exe_data.name] = exe_data
       
    
    def update_data(self,exe_data: ExeData):
        
        for row in range(self.TableWidget.rowCount()):
            item = self.TableWidget.item(row, 1)
            if item and item.text() == exe_data.path:
                # 找到对应的行，更新数据
                recv_bytes = round(exe_data.recv_bytes, 2)
                send_bytes = round(exe_data.send_bytes, 2)      
                recv_speed = round(exe_data.recv_speed, 2)
                send_speed = round(exe_data.send_speed, 2)
                ipv4_recv_bytes = round(exe_data.ipv4_recv_bytes, 2)
                ipv4_send_bytes = round(exe_data.ipv4_send_bytes, 2)
                ipv6_recv_bytes = round(exe_data.ipv6_recv_bytes, 2)
                ipv6_send_bytes = round(exe_data.ipv6_send_bytes, 2)
                
                self.TableWidget.setItem(row, 2, QTableWidgetItem(str(recv_bytes)+self.speed_unit.MB))
                self.TableWidget.setItem(row, 3, QTableWidgetItem(str(send_bytes)+self.speed_unit.MB))
                self.TableWidget.setItem(row, 4, QTableWidgetItem(str(recv_speed)+self.speed_unit.MB_per))
                self.TableWidget.setItem(row, 5, QTableWidgetItem(str(send_speed)+self.speed_unit.MB_per))
                self.TableWidget.setItem(row, 6, QTableWidgetItem(str(exe_data.recv_packets)))
                self.TableWidget.setItem(row, 7, QTableWidgetItem(str(exe_data.send_packets)))

                self.TableWidget.setItem(row, 8, QTableWidgetItem(str(ipv4_recv_bytes)+ self.speed_unit.MB))
                self.TableWidget.setItem(row, 9, QTableWidgetItem(str(ipv4_send_bytes)+ self.speed_unit.MB))
                self.TableWidget.setItem(row, 10, QTableWidgetItem(str(ipv6_recv_bytes)+ self.speed_unit.MB))
                self.TableWidget.setItem(row, 11, QTableWidgetItem(str(ipv6_send_bytes)+ self.speed_unit.MB))
                break
    
    
        
if __name__ == '__main__':
    app=QApplication(sys.argv)
    win=Table()

    win.show()
    sys.exit(app.exec_())