#-*- coding: UTF-8 -*-


from sklearn import tree
from sklearn.externals import joblib
import re
import sys
import platform

# 计算指定数据集中每一行特征向量值
def trained(data):
    features = list()
    lables = list()
    passwords = list()
    t = 0
    f = open(data, "r")
    # with open(data) as f:
    for password in f:
        t += 1
        print t
        feature = getfeatures(password)
        features.append(feature)
        lable = getlable(feature)
        lables.append(lable)
        passwords.append(password)
    f.close()
    return [features,  lables, passwords]


# 生成决策树模型并保存到本地
def decisiontree(file1, file2):
    trainingData = training(file1)
    clf = tree.DecisionTreeClassifier(criterion='entropy')
    clf = clf.fit(trainingData[0], trainingData[1])
    joblib.dump(clf, file2)


# 加大复杂密码training集标签值
def pretrained2(data):
    features = list()
    lables = list()
    passwords = list()
    t = 0
    f = open(data, "w")
    for password in f:
        t += 1
        print t
        lable = password.split('|')[1].strip('\n')
        lables.append(lable)
        passwords.append(password[:-3])
    thefile = open('training_models/training2.txt', 'a')
    for st in range(0, len(passwords)):
        if int(lables[st]) + 4 > 10:
            thelable = 10
        else:
            thelable = int(lables[st]) + 4
        thefile.write(str(passwords[st]).strip('\n')+'|'+str(thelable)+'\n')
    thefile.close()
    f.close()
    return [features,  lables, passwords]


# training集生成完毕后,可以直接调用本函数获取传入decision tree的参数
def training(data):
    features = list()
    lables = list()
    passwords = list()
    t = 0
    f = open(data, "r")
    for password in f:
        if password == "":
            continue
        t += 1
        print t
        result = password.split('|')
        feature = getfeatures(result[0])
        features.append(feature)
        lable = result[1].strip('\n')
        lables.append(lable)
        passwords.append(password)
    f.close()
    return [features, lables, passwords]


# 提取指定测试集的特征,作为输入参数,从而得到分类
# data为测试集文件，默认testing.txt
def testing(data):
    features = list()
    f = open(data, "r")
    for password in f:
        features.append(getfeatures(password))
    print features
    return features

'''
def validating(data):
    f = open(data, "w")
    for password in f:
        features.append(getfeatures(password[:-3]))
    #print features
    return features
'''

# 提取指定测试集的特征,作为输入参数,从而得到分类
# data为测试集文件，默认testing.txt
def singletesting(data):
    features = list()
    features.append(getfeatures(data))
    print features
    return features


# 取lable
def getlable(feature):
    sum1 = 0
    for a in feature:
        sum1 += a
    return sum1


#生成training集标签值
def pretrained(data):
    features = list()
    lables = list()
    passwords = list()
    t = 0
    f = open(data, "w")
    for password in f:
        t += 1
        print t
        feature = getfeatures(password)
        features.append(feature)
        lable = getlable(feature)
        lables.append(lable)
        passwords.append(password)
    thefile = open('training_models/training2.txt', 'a')
    for st in range(0, len(passwords)):
        if int(lables[st]) - 3 < 0:
            thelable = 0
        else:
            thelable = int(lables[st]) -3
        thefile.write(str(passwords[st]).strip('\n')+'|'+str(thelable)+'\n')
    thefile.close()
    f.close()
    return [features,  lables, passwords]

# 将密码进行结构化处理
def getstructure(strdata):
    data = strdata.strip('\n')
    struc = ''
    for u in data:
        if ((u >= 'a') and u <= 'z') or ((u >= 'A') and u <= 'Z'):
            struc += '0'
        elif (u >= '0') and u <= '9':
            struc += '1'
        else:
            struc += '2'
    return struc


# 提取密码特征,返回指定词的特征向量集
# data为需要计算特征的某条密码
def getfeatures(data):
    l = data.strip('\n')
    # 经典，结构，键位，单词，拼音
    feature = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    lenMin = False  # no more than 6 chars
    specChar = False  # special character
    ucChar = False  # uppercase character
    numChar = False  # numeric character
    if len(l) <= 6:
        lenMin = True
    specialMatch = re.search(r'([^a-zA-Z0-9]+)', l, re.M)
    if specialMatch:
        specChar = True
    ucMatch = re.search(r'([A-Z])', l, re.M)
    if ucMatch:
        ucChar = True
    numMatch = re.search(r'([0-9])', l, re.M)
    if numMatch:
        numChar = True

    # 经典规则,长度、大小写、特殊符号等
    if lenMin:
        feature[0] = 0
    if ucChar and numChar:
        feature[5] = 1
    if specChar and numChar:
        feature[6] = 1
    if ucChar:
        feature[7] = 2
    if specChar:
        feature[8] = 3
    if specChar and ucChar and numChar:
        feature[9] = 3.5
    if len(l) >= 10:
        for a in range(0, 10):
            feature[a] += 1
    # 结构规则,基于密码结构分析结果
    struc_list = []
    length = len(data) - 1
    if length < 6:
        feature[1] = 0
    elif length > 10:
        feature[1] = 2
    else:
        struc = getstructure(data)
        inputfile = open('analysis_lib/struc_lib_'+str(length)+'.txt', 'r')
        for line in inputfile:
            if line != "":
                clenline = line.strip('\n')
                struc_list.append(clenline)
        if (struc == struc_list[0]) or struc == struc_list[1] or struc == struc_list[2] or struc == struc_list[3]:
            feature[1] = 0
        elif struc == struc_list[4] or struc == struc_list[5] or struc == struc_list[6] or struc == struc_list[7] or struc == struc_list[8] or struc == struc_list[9]:
            feature[1] = 1
        else:
            feature[1] = 2
        inputfile.close()

    # 拼音规则,基于163高频拼音分析结果
    inputfile1 = open('analysis_lib/pinyin_top.txt', 'r')
    feature[2] = 1
    for line in inputfile1:
        cleanline = line.strip('\n')
        if cleanline == "":
            continue
        if cleanline in data:
            feature[2] = 0
            break
    inputfile1.close()


    # 英文单词规则,基于高频单词分析结果
    inputfile2 = open('analysis_lib/english_lib.txt', 'r')
    feature[3] = 1
    for line1 in inputfile2:
        cline = line1.strip('\n')
        if cline == "":
            continue
        if data.find(cline) != -1:
            feature[3] = 0
            break
    inputfile2.close()

    # 键位规则,基于高频键位分析结果
    inputfile4 = open('analysis_lib/keyboard_lib.txt', 'r')
    feature[4] = 2
    for line2 in inputfile4:
        clearline = line2.strip('\n')
        if clearline == "":
            continue
        if data.find(clearline) != -1:
            feature[4] = 0
            break
    inputfile4.close()
    return feature


# 传入文件类型测试集
def getfiletest(filename):
    passwords = list()
    f = open(filename)
    for password in f:
        passwords.append(password.strip('\n'))
    print passwords
    f.close()
    mldtr = joblib.load("training_models/train_model2.m")
    featuredata = testing(filename)
    prediction = mldtr.predict(featuredata)
    k = 0
    answer = open("predict_answer", "w")
    answer.write("------------------------------------------------\n")
    answer.write("密码强度分为Level 0 到Level 4 五档\n")
    answer.write("一般可认为0为极弱密码,1为弱密码,2-3为中等强度密码,4为较高强度密码\n")
    answer.write("------------------------------------------------\n")
    for i in prediction:
        if i == '2':
            i = '1'
        if i == '3' or i == '4':
            i = '2'
        if i == '5' or i == '6':
            i = '3'
        if i == '6' or i == '7' or i == '8':
            i = '4'
        answer.write("序号:" + str(k) + " 密码:"+passwords[k] + "     ------Level "+i+'\n')
        k += 1
        print i, k
    answer.close()


# 传入单个测试数据
def getsingletest(password):
    mldtr = joblib.load("training_models/train_model2.m")
    featuredata = singletesting(password)
    prediction = mldtr.predict(featuredata)
    print prediction
    k = 0
    answer = open("predict_answer", "w")
    answer.write("------------------------------------------------\n")
    answer.write("密码强度分为Level 0 到Level 4 五档\n")
    answer.write("一般可认为0为极弱密码,1为弱密码,2-3为中等强度密码,4为较高强度密码\n")
    answer.write("------------------------------------------------\n")
    for i in prediction:
        if i == '2':
            i = '1'
        if i == '3' or i == '4':
            i = '2'
        if i == '5' or i == '6':
            i = '3'
        if i == '6' or i == '7' or i == '8':
            i = '4'
        k += 1
        answer.write("序号:" + str(k) + " 密码:"+password.strip('\n') + "     ------Level "+i)
        print i, k
    answer.close()

'''
# 验证
def getvalidtest(filename):
    mldtr = joblib.load("training_models/train_model2.m")
    featuredata = validating(filename)
    prediction = mldtr.predict(featuredata)
    targets = list()
    target = open("validate", "r")
    print prediction
    for j in target:
        targets.append(j.strip('\n')[-1:])
    current = 0
    for i in range(0, len(prediction)):
        print targets[i]
        if prediction[i] != targets[i]:
            current += 1
            print str(current)+' incorrect! '+ str(prediction[i])+ str(targets[i])
'''

def main(argv):
    for arg in argv:
        print arg


if __name__ == "__main__":
    # 生成training.txt
    '''
    trainingData = pretrained('files/pass163')
    trainingData = pretrained2('files/training.txt')
    '''

    # decisiontree("training_models/training2.txt", "training_models/train_model2.m")

    # getsingletest('@Fl!pm0de12@\n')
    # getfiletest('testing')
    # getvalidtest('validate')


    main(sys.argv)
    if sys.argv[1] == '1':
        print sys.argv[2]
        getfiletest(sys.argv[2]);
    if sys.argv[1] == '2':
        getsingletest(sys.argv[2]);
