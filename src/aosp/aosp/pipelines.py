# -*- coding: utf-8 -*-

# Define your item pipelines here
#
# Don't forget to add your pipeline to the ITEM_PIPELINES setting
# See: http://doc.scrapy.org/en/latest/topics/item-pipeline.html
import sqlite3

class AospPipeline(object):
    def process_item(self, item, spider):
        return item


class Sqlite3Pipeline(object):

    def __init__(self, sqlite_file, sqlite_table):
        self.sqlite_file = sqlite_file
        self.sqlite_table = sqlite_table
        
    @classmethod
    def from_crawler(cls, crawler):
        return cls(
            sqlite_file = crawler.settings.get('SQLITE_FILE'), # 从 settings.py 提取
            sqlite_table = crawler.settings.get('SQLITE_TABLE', 'items')
        )
    def create_tables(self):
        self.drop_table()
        self.create_table()

    def drop_table(self):
        #drop amazon table if it exists
        self.cur.execute("DROP TABLE IF EXISTS dmoz")

    def create_table(self):
        create_sql = """CREATE TABLE IF NOT EXISTS 
            dmoz(id INTEGER PRIMARY KEY NOT NULL, 
            cve_id TEXT, 
            m_references TEXT, 
            severity TEXT, 
            devices TEXT, 
            versions TEXT, 
            report_date TEXT, 
            create_time TEXT, 
            update_time TEXT,
            file_path TEXT, 
            bulletins_date TEXT 
            )"""

        self.cur.execute(create_sql)

    def open_spider(self, spider):
        self.conn = sqlite3.connect(self.sqlite_file)
        self.cur = self.conn.cursor()
        print('open spider...')
        self.create_tables()

    def close_spider(self, spider):
        self.conn.close()

    def process_item(self, item, spider):
        insert_sql = "insert into {0}({1}) values ({2})".format(self.sqlite_table, 
                                                                ', '.join(item.keys()),
                                                                ', '.join(['?'] * len(item.keys())))
        self.cur.execute(insert_sql, item.values())
        self.conn.commit()
        
        return item