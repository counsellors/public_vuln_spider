# -*- coding: utf-8 -*-
import scrapy
import os
from scrapy.selector import Selector
from nnd.items import NndItem

class XspiderSpider(scrapy.Spider):
    name = "xspider"
    allowed_domains = ["www.cnnvd.org.cn"]
    start_urls = [
    'http://www.cnnvd.org.cn/vulnerability/show/cv_cnnvdid/CNNVD-201504-584',
    'http://www.cnnvd.org.cn/vulnerability/show/cv_cnnvdid/CNNVD-201504-584',
    'http://www.cnnvd.org.cn/vulnerability/show/cv_cnnvdid/CNNVD-201507-462',
    'http://www.cnnvd.org.cn/vulnerability/show/cv_cnnvdid/CNNVD-201507-438',
    'http://www.cnnvd.org.cn/vulnerability/show/cv_cnnvdid/CNNVD-201507-439',
    'http://www.cnnvd.org.cn/vulnerability/show/cv_cnnvdid/CNNVD-201507-459',
    'http://www.cnnvd.org.cn/vulnerability/show/cv_cnnvdid/CNNVD-201507-463',
    'http://www.cnnvd.org.cn/vulnerability/show/cv_cnnvdid/CNNVD-201507-470',
    'http://www.cnnvd.org.cn/vulnerability/show/cv_cnnvdid/CNNVD-201507-452',
    'http://www.cnnvd.org.cn/vulnerability/show/cv_cnnvdid/CNNVD-201507-453',
    'http://www.cnnvd.org.cn/vulnerability/show/cv_cnnvdid/CNNVD-201507-454',
    'http://www.cnnvd.org.cn/vulnerability/show/cv_cnnvdid/CNNVD-201507-456',
    'http://www.cnnvd.org.cn/vulnerability/show/cv_cnnvdid/CNNVD-201507-457',
    'http://www.cnnvd.org.cn/vulnerability/show/cv_cnnvdid/CNNVD-201507-458',
    'http://www.cnnvd.org.cn/vulnerability/show/cv_cnnvdid/CNNVD-201507-471',
    'http://www.cnnvd.org.cn/vulnerability/show/cv_cnnvdid/CNNVD-201507-460',
    'http://www.cnnvd.org.cn/vulnerability/show/cv_cnnvdid/CNNVD-201507-461',
    'http://www.cnnvd.org.cn/vulnerability/show/cv_cnnvdid/CNNVD-201507-446',
    'http://www.cnnvd.org.cn/vulnerability/show/cv_cnnvdid/CNNVD-201507-445',
    'http://www.cnnvd.org.cn/vulnerability/show/cv_cnnvdid/CNNVD-201507-443',
    'http://www.cnnvd.org.cn/vulnerability/show/cv_cnnvdid/CNNVD-201507-447',
    'http://www.cnnvd.org.cn/vulnerability/show/cv_cnnvdid/CNNVD-201507-451',
    'http://www.cnnvd.org.cn/vulnerability/show/cv_cnnvdid/CNNVD-201507-448',
    'http://www.cnnvd.org.cn/vulnerability/show/cv_cnnvdid/CNNVD-201507-444',
    'http://www.cnnvd.org.cn/vulnerability/show/cv_cnnvdid/CNNVD-201507-465',
    'http://www.cnnvd.org.cn/vulnerability/show/cv_cnnvdid/CNNVD-201507-442',
    'http://www.cnnvd.org.cn/vulnerability/show/cv_cnnvdid/CNNVD-201507-440',
    'http://www.cnnvd.org.cn/vulnerability/show/cv_cnnvdid/CNNVD-201507-464',
    'http://www.cnnvd.org.cn/vulnerability/show/cv_cnnvdid/CNNVD-201507-466',
    'http://www.cnnvd.org.cn/vulnerability/show/cv_cnnvdid/CNNVD-201505-567',
    ]

    def get_value(self, sel, pattern):
        ret = sel.xpath(pattern).extract()
        if len(ret) > 0:
            return str( ret[0].encode('utf-8') ).strip()
        else:
            return ''
    def parse(self, response):
        sel = Selector(response)
        item = NndItem()
        item['link'] = response.url
        item['attack_method'] = self.get_value(sel, '//*[@id="__01"]/tr/td/table/tr[1]/td/div/table/tr[7]/td[2]/a/text()') 
        item['vuln_name'] = self.get_value(sel, '//*[@id="__01"]/tr/td/table/tr[1]/td/div/table/tr[1]/td[2]/text()')
        item['cnnvd_id'] = self.get_value(sel, '//*[@id="__01"]/tr/td/table/tr[1]/td/div/table/tr[2]/td[2]/text()')
        item['release_date'] = self.get_value(sel, '//*[@id="__01"]/tr/td/table/tr[1]/td/div/table/tr[3]/td[2]/a/text()')
        item['update_date'] = self.get_value(sel, '//*[@id="__01"]/tr/td/table/tr[1]/td/div/table/tr[4]/td[2]/a/text()')

        item['severity'] = self.get_value(sel, '//*[@id="__01"]/tr/td/table/tr[1]/td/div/table/tr[5]/td[2]/a/text()')
        item['vuln_type'] = self.get_value(sel, '//*[@id="__01"]/tr/td/table/tr[1]/td/div/table/tr[6]/td[2]/a/text()')
        item['cve_id'] = self.get_value(sel, '//*[@id="__01"]/tr/td/table/tr[1]/td/div/table/tr[8]/td[2]/a/text()')
        print item
        filename = "x.sql"
        with open(filename,'a') as fp:
            fp.write("update cve_desc set attack_method='%s' where cnnvd_id='%s';\n"%(item['attack_method'], item['cnnvd_id'] ))
