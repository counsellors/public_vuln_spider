# -*- coding: utf-8 -*-
import scrapy
import urllib2
from aosp.items import AospItem
from scrapy.selector import Selector
from scrapy.spiders import CrawlSpider, Rule
from scrapy.linkextractors import LinkExtractor

class AndroidSecSpider(CrawlSpider):
    name = 'android_sec'
    allowed_domains = ['source.android.com',
                        'android.googlesource.com']
    start_urls = ['https://source.android.com/security/bulletin']
    debug = 0
    rules = None
    if debug == 1:
        rules = (
            Rule(LinkExtractor(allow=('security/bulletin/2017-05-\d\d$', )), 
                callback='parse_item'),
        )
    else:
        rules = (
            Rule(LinkExtractor(allow=('security/bulletin/20\d\d-\d\d-\d\d$', )), 
                callback='parse_item'),
        )


    def get_ref(self,sel):
        refers = []
        if len(sel.xpath("a")) == 0:
            refers = ";".join(sel.xpath("text()").extract())
            return refers
        else:
            for row in sel.xpath("a"):
                # refer={
                #     'href': row.xpath("@href").extract(),
                #     'ref_name' : row.xpath("text()").extract()
                # }
                refer = row.xpath("@href").extract()[0]
                refers.append(refer)
            refers = ";".join(refers)
            self.logger.info('get_ref refers: %s'% refers)
            return refers
                
                
    def parse_item(self, response):
        self.logger.info('Hi, this is an item page! %s', response.url)
        sel = Selector(response)
        last_cve = ""
        found_flag = 0
        for row in sel.xpath('//*[@id="gc-wrapper"]/div/devsite-content/article/article/div[2]/table/tr[not(child::th)]'):
        # for row in sel.xpath('//*[@id="gc-wrapper"]/div[2]/article/article/div[1]/table/tr[not(child::th)]'):
            found_flag = 1
            self.logger.info("*********found_flag:1************")
            item = AospItem()
            item['bulletins_date'] = response.url.split("/")[-1] 
            self.logger.info('td length: %s', len(row.xpath('td')))
            self.logger.info('td: %s', row.extract())
            if len(row.xpath('td')) == 5:
                # why cve_id is td[1], not td[0]?
                item['cve_id'] = row.xpath('td[1]/text()').extract()[0]
                # the field named references will conflict with sqlite3's statement
                item['m_references']  = self.get_ref(row.xpath('td[2]'))
                item['severity'] = row.xpath('td[3]/text()').extract()[0]
                item['devices'] = row.xpath('td[4]/text()').extract()[0]
                item['report_date'] = row.xpath('td[5]/text()').extract()[0]
            elif len(row.xpath('td')) == 6:
                item['cve_id'] = row.xpath('td[1]/text()').extract()[0]
                item['m_references']  = self.get_ref(row.xpath('td[2]'))
                item['severity'] = row.xpath('td[3]/text()').extract()[0]
                item['devices'] = row.xpath('td[4]/text()').extract()[0]
                item['versions'] = row.xpath('td[5]/text()').extract()[0]
                item['report_date'] = row.xpath('td[6]/text()').extract()[0]
            elif len(row.xpath('td')) == 4:

                if not self.get_ref(row.xpath('td[1]')).startswith("CVE"):
                    item['cve_id'] = last_cve
                    item['m_references'] = self.get_ref(row.xpath('td[1]'))
                    item['severity']  = row.xpath('td[2]/text()').extract()[0]
                    item['devices'] = row.xpath('td[3]/text()').extract()[0]
                else:
                    item['cve_id'] = row.xpath('td[1]/text()').extract()[0]
                    item['m_references']  = self.get_ref(row.xpath('td[2]'))
                    item['severity'] = row.xpath('td[3]/text()').extract()[0]
                    item['versions'] = row.xpath('td[4]/text()').extract()[0]
            else:
                continue
            self.logger.info( 'ending of cve id: %s parse'%item['cve_id'])
            if not item['cve_id'].startswith("CVE"):
                continue
            last_cve = item['cve_id']
            if item['m_references'] is not None \
                and item['m_references'].startswith("https://android."):
                urls = item['m_references'].split(";")
                for url in urls:
                    # get vul file path from diff link.
                    # call the next page parser for diff link
                    request = scrapy.Request(url,callback=self.parse_diff)
                    # the first item passed by request's meta attr
                    request.meta['item'] = item
                    # not return but iter to parse 
                    yield request
            else:
                yield item

    def parse_diff(self, response):
        item = response.meta['item']
        self.logger.info('Hi, this is the second item page! %s', response.url)
        m_path = '/html/body/div/div/ul/li'
        all_path = []
        for row in response.xpath('/html/body/div/div/ul/li/a/text()'):
            first_part = response.url.split("+")[0]
            full_url = first_part+row.extract()
            full_decoded_url = urllib2.unquote(full_url)
            all_path.append(full_decoded_url)
        item["file_path"] = ";".join(all_path)
        yield item

    