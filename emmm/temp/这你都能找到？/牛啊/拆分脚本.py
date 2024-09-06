import sys,re,os

if len(sys.argv)>=2:
    file = sys.argv[1]
else:
    print("请输入文件，python cfmd.py 文件名")
    exit()

# poc_dir = file.replace('.md','')
poc_dir = "poc"
if os.path.exists(poc_dir):
    print("[-] {}目录或文件已存在！".format(poc_dir))
    fffflag = input("是否直接使用？直接使用，目录下存在同名文件会被覆盖。（Y/N）:")
    if  fffflag.lower() != "y":
        exit()
else:
    os.mkdir(poc_dir)

filelist = [
    {'category':'金和OA','keywords':['金和','金和OA']},
    {'category':'泛微OA','keywords':['泛微','e-cology','weaver']},
    {'category':'用友','keywords':['用友','yonyou','畅捷通','畅捷CRM']},
    {'category':'I Doc View','keywords':['I Doc View','IDocView']},
    {'category':'海康威视','keywords':['HIKVISION','海康']},
    {'category':'大华','keywords':['大华','dahua']},
    {'category':'WordPress','keywords':['WordPress']},
    {'category':'Nacos','keywords':['Nacos']},
    {'category':'Jeecg-Boot','keywords':['JeecgBoot','jeecg-boot','Jeecg Boot']},
    {'category':'广联达','keywords':['广联达','联达OA']},
    {'category':'安恒','keywords':['安恒','明御']},
    {'category':'绿盟','keywords':['绿盟']},
    {'category':'奇安信','keywords':['奇安信','天擎']},
    {'category':'锐捷','keywords':['锐捷','Ruijie']},
    {'category':'深信服','keywords':['深信服']},
    {'category':'通达OA','keywords':['通达OA','通达 oa']},
    {'category':'亿赛通','keywords':['亿赛通']},
    {'category':'致远OA','keywords':['致远','Seeyon']},
    {'category':'蓝凌OA','keywords':['蓝凌']},
    {'category':'帆软报表','keywords':['帆软']},
    {'category':'万户OA','keywords':['万户OA','万户 ezOFFICE','万户ezOFFICE','万户协同办公平台']},
    {'category':'天融信','keywords':['天融信']},
    {'category':'宏景eHR','keywords':['宏景']},
    {'category':'红帆OA','keywords':['红帆OA','红帆 OA']},
    {'category':'金蝶','keywords':['金蝶']},
    {'category':'瑞友天翼','keywords':['瑞友天翼']},
    {'category':'时空智友','keywords':['时空智友']},
    {'category':'浙大恩特','keywords':['浙大恩特']},
    {'category':'通天星','keywords':['通天星']},
    {'category':'思福迪','keywords':['思福迪']},
    {'category':'启明星辰','keywords':['天玥','启明星辰']},
    {'category':'飞企互联','keywords':['飞企互联']},
    {'category':'禅道','keywords':['禅道']},
    {'category':'帮管客 CRM','keywords':['帮管客']},
    {'category':'VMware','keywords':['VMware']},
    {'category':'TP-Link','keywords':['TP-Link']},
    {'category':'Telesquare','keywords':['Telesquare']},
    {'category':'SmartBI','keywords':['SmartBI']},
    {'category':'nginxWebUI','keywords':['nginxWebUI']},
    {'category':'JumpServer','keywords':['JumpServer']},
    {'category':'Juniper','keywords':['Juniper']},
    {'category':'Joomla','keywords':['Joomla']},
    {'category':'JeePlus快速开发平台','keywords':['JeePlus快速开发平台']},
    {'category':'H3C','keywords':['H3C','华三']},
    {'category':'GitLab','keywords':['GitLab']},
    {'category':'D-Link','keywords':['D-Link','DLink']},
    {'category':'Adobe ColdFusion','keywords':['Adobe ColdFusion']},
    {'category':'Apache Dubbo','keywords':['Apache Dubbo']},
    {'category':'Apache ActiveMQ','keywords':['Apache ActiveMQ']},
    {'category':'Apache OFBiz','keywords':['Apache OFBiz']},
    {'category':'Atlassian Confluence','keywords':['Atlassian Confluence']},
    {'category':'Apache Solr','keywords':['Apache Solr']},
    {'category':'Cacti','keywords':['Cacti']},
    {'category':'Cisco','keywords':['Cisco','思科']},
    {'category':'DedeCMS','keywords':['DedeCMS']},
    {'category':'Draytek','keywords':['Draytek']},
    {'category':'EduSoho 教培系统','keywords':['EduSoho']},
    {'category':'F5 BIG','keywords':['F5 BIG']},
    {'category':'kkFileView','keywords':['kkFileView']},
    {'category':'KingPortal开发系统','keywords':['KingPortal']},
    {'category':'jshERP','keywords':['jshERP']},
    {'category':'Netgear','keywords':['Netgear']},
    {'category':'OfficeWeb365','keywords':['OfficeWeb365']},
    {'category':'OpenMetadata','keywords':['OpenMetadata']},
    {'category':'Oracle Weblogic','keywords':['Weblogic']},
    {'category':'Panabit','keywords':['Panabit']},
    {'category':'北京百绰智能','keywords':['百卓Smart','北京百绰智能']},
    {'category':'大唐电信','keywords':['大唐电信']},
    {'category':'福建科立讯通信有限公司指挥调度管理平台','keywords':['福建科立讯通信']},
    {'category':'易宝OA','keywords':['易宝OA']},
    {'category':'中成科信票务管理平台','keywords':['中成科信票务管理平台','中城科信票务管理']},
    {'category':'云时空ERP','keywords':['云时空ERP','云时空商业ERP']},
    {'category':'西软云','keywords':['西软云']},
    {'category':'interlib3图书馆集群管理系统','keywords':['interlib3','图书馆集群']},
    {'category':'天问物业ERP系统','keywords':['天问物业ERP系统']},
    {'category':'深澜计费管理系统','keywords':['深澜计费管理系统']},
    {'category':'赛蓝企业管理系统','keywords':['赛蓝企业管理系统']},
    {'category':'润乾报表平台','keywords':['润乾报表']},
    {'category':'契约锁电子签章系统','keywords':['契约锁']},
    {'category':'脸爱云一脸通智慧平台','keywords':['脸爱云一脸通智慧平台']},
    {'category':'蓝海卓越计费管理系统','keywords':['蓝海卓越计费管理系统']},
    {'category':'科荣AIO管理系统','keywords':['科荣AIO','科荣 AIO']},
    {'category':'WeiPHP','keywords':['WeiPHP']}
]

file_list = []
final_file = []
obj = re.compile('^## [0-9]{1,3}\.?')
with open(file,mode='r',encoding='utf-8') as f:
    for i in f:
        file_list.append(i)

for i in file_list:
    if obj.match(i):
        str = obj.match(i).group()
        filename = i.replace('\n', '')
        filename = filename.replace(str, '')
        if filename.startswith(' '):
            filename = filename[1:]
        # print(filename)
        filename1 = filename.replace('/', ' ')
        filename1 = filename1.replace('|', ' ')
        filename1 = filename1.replace('<=', '小于等于')
        filename1 = filename1.replace('<', '小于')
        filename1 = re.sub(r'\s{2,}',' ',filename1)
        final_file.append(filename1 + ".md")
        filename1 = poc_dir + os.sep + filename1
        flag = False
        with open(filename1 + ".md",mode='w',encoding='utf-8') as wf:
            for j in file_list:
                if filename in j:
                    flag = True
                    j = "## " + filename
                    wf.write(j)
                    continue
                if flag and obj.match(j):
                    break
                if flag:
                    wf.write(j)

for fff in final_file:
    mv_flag = 0
    for ttt in filelist:
        ttt_path = poc_dir + os.sep + ttt['category']
        for kkk in ttt['keywords']:
            if kkk.lower() in fff.lower():
                sfile = poc_dir + os.sep + fff
                dfile = ttt_path + os.sep + fff
                print(f"Checking {fff} for keyword '{kkk}'")  # 调试输出
                if not os.path.exists(ttt_path):
                    os.mkdir(ttt_path)
                    print(f"Created directory {ttt_path}")
                if os.path.exists(dfile):
                    os.remove(dfile)
                    print(f"Removed existing file {dfile}")
                if os.path.exists(sfile):  # 确认文件存在
                    os.rename(sfile, dfile)
                    print(f"Moved {sfile} to {dfile}")
                    mv_flag = 1
                    break
                else:
                    print(f"File not found: {sfile}")  # 如果文件不存在，打印错误信息
        if mv_flag == 1:
            break